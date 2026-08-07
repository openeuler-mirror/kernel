/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 VeriSilicon Holdings Co., Ltd.
 */

#ifndef __VS_TYPE_H__
#define __VS_TYPE_H__

#include <drm/drm_plane.h>
#include <drm/drm_plane_helper.h>
#include "vs_egt_drm.h"

#ifdef CONFIG_DEBUG_FS
#define MAX_CRC_NUM 16
#endif

/* Compile time assert */
#define vs_dc_ct_assert(cond, msg) __vs_dc_assert_impl(cond, __LINE__, msg)
#define __vs_dc_assert_paste(msg, line) msg##line
#define __vs_dc_assert_impl(cond, line, msg) \
	typedef char __vs_dc_assert_paste(assert_failed_##msg##_, line)[2 * !!(cond) - 1]

struct vs_plane_info {
	const char *name;
	u8 id;
	enum drm_plane_type type;
	u8 crtc_id; /* default crtc index, only for primary plane */
	unsigned int num_formats;
	const u32 *formats;
	u8 num_modifiers;
	const u64 *modifiers;
	unsigned int num_support_custom_formats;
	const u32 *support_custom_formats;
	const u64 *rot_supp_mods; /* the modifiers supported for rotation */
	unsigned int min_width;
	unsigned int min_height;
	unsigned int max_width;
	unsigned int max_height;
	unsigned int rotation;
	unsigned int blend_mode;
	unsigned int color_encoding;
	unsigned int color_range;

	/* 0 means no de-gamma LUT */
	unsigned int degamma_size;

	int min_scale; /* 16.16 fixed point */
	int max_scale; /* 16.16 fixed point */

/* default zorder value,
 * and 255 means unsupported zorder capability
 */
	u8 zpos;

	u8 max_uv_phase; /* for uv up-sampling */

	u32 color_mgmt : 1;
	u32 program_csc : 1;
	u32 roi : 1;
	u32 roi_two : 1;
	u32 roi_skip : 1;
	u32 layer_ext : 1;
	u32 multi_layer_ext : 1;
	u32 layer_ext_ex : 1;
	u32 cgm_lut : 1;
	u32 alpha_ext : 1;
	u32 demultiply : 1;
	u32 hdr : 1;
	u32 tone_map : 1;
	u32 blend_config : 1; /* for BLEND_MODE, BLEND_ALPHA properties */
	u32 crc : 1;
	u32 test_pattern : 1;
	u32 compressed : 1;
	u32 watermark : 1;
	u32 sbs : 1;
	u32 line_padding : 1;
	u32 gamut_map : 1;
	u32 layer_crop : 1;
	u32 ccm : 1;
	u32 degamma : 1;
	u32 fast_clear : 1;
};

/*for dsc and vdc size */
struct dec_size_info {
	u32 max_w;
	u32 max_h;
	u32 slice_max_w;
	u32 slice_max_h;
	u64 pixel_count;
};

struct vs_display_info {
	const char *name;
	u8 id;
	unsigned int color_formats;
	unsigned int max_width;
	unsigned int max_height;

	int min_scale; /* 16.16 fixed point */
	int max_scale; /* 16.16 fixed point */

	u32 invalid : 1;
	u32 background : 1;
	u32 bld_cgm : 1; /* for blend EOTF, gamut map modules */
	u32 bld_oetf : 1;
	u32 bld_dth : 1;
	u32 gamma_dth : 1;
	u32 panel_dth : 1;
	u32 llv_dth : 1;
	u32 ltm : 1; /* local tone mapping module */
	u32 gtm : 1;
	u32 sharpness : 1;
	u32 brightness : 1;
	u32 degamma : 1;
	u32 gamma : 1;
	u32 ccm_non_linear : 1;
	u32 ccm_linear : 1;
	u32 cgm_lut : 1;
	u32 lut_roi : 1;
	u32 blur : 1;
	u32 sec_roi : 1;
	u32 data_mode : 1;
	u32 rcd : 1;
	u32 histogram : 1;
	u32 rgb_hist : 1;
	u32 crc : 1;
	u32 test_pattern : 1;
	/* write-back point validity */
	u32 disp_in_wb : 1;
	u32 disp_cc_wb : 1;
	u32 disp_out_wb : 1;
	u32 ofifo_in_wb : 1;
	u32 ofifo_out_wb : 1;
	u32 decompress : 1;
	u32 dsc : 1;
	u32 vdc : 1;
	u32 spliter : 1;
	u32 free_sync : 1;
	u32 panel_crop : 1;
	u32 dp_sync : 1;
	u32 ofifo_splice : 1;
	u32 bld_nonlinear_gamut : 1;
	const struct dec_size_info *dsc_size;
	const struct dec_size_info *vdc_size;
};

struct vs_output_info {
	const char *name;
	u16 mux_id;
	u32 type;
	u32 output_mode;
	u32 max_w;
	u32 max_h;
};

struct vs_wb_info {
	const char *name;
	u8 id;
	unsigned int num_formats;
	const u32 *formats;
	const u64 *modifiers;
	unsigned int num_support_custom_formats;
	const u32 *support_custom_formats;
	unsigned int max_width;
	unsigned int max_height;
	unsigned int rotation;

	int min_scale; /* 16.16 fixed point */
	int max_scale; /* 16.16 fixed point */

	u8 src_mask; /* the mask of valid display path*/

	u8 program_point : 1;
	u32 init_wb_point;
	u8 dither : 1;
	u8 csc : 1; /* for R2Y */
	u8 crc : 1;
	u8 compressed : 1;
	u8 spliter : 1;
	u32 data_mode : 1; /* for data extend */
	u8 crop : 1;
	u8 gamma_dither : 1;
	u8 gamma : 1;
};

struct vs_dc_info {
	const char *name;
	u32 chip_id;
	u32 revision;
	u32 pid;
	u32 cid;

	/* planes */
#if ((defined(CONFIG_ENGIANT_VS_CHIP_9x00) && (CONFIG_ENGIANT_VS_CHIP_9x00)) || \
(defined(CONFIG_ENGIANT_VS_CHIP_9000SR) && (CONFIG_ENGIANT_VS_CHIP_9000SR)))
	u8 plane_num;
	u8 plane_fe0_num;
	u8 plane_fe1_num;
	const struct vs_plane_info *planes_fe0;
	const struct vs_plane_info *planes_fe1;
	const struct format_limit_info *format_limit;
	u8 format_limit_size;
	u8 layer_num;
	u8 layer_fe0_num;
	u8 layer_fe1_num;
#else
	u8 plane_num;
	const struct vs_plane_info *planes;
	u8 layer_num;
#endif
	/* display */
	u8 display_num;
	const struct vs_display_info *displays;

	/* output */
	u8 output_num;

	/* write back */
	u8 wb_num;
	const struct vs_wb_info *write_back;

	/* DSC */
	const struct dsc_hw_config *dsc_hw_config;

	unsigned int max_bpc;
	u16 pitch_alignment;
	u16 addr_alignment;

	/* SRAM POOL SIZE (Kbytes) */
	u16 fe0_dma_sram_size;
	u16 fe1_dma_sram_size;
	u16 fe0_scl_sram_size;
	u16 fe1_scl_sram_size;

	u8 max_blend_layer;
	u8 max_ext_layer;
	u8 max_seg_num;

	/* LUT requirement */
	u16 max_eotf_size;
	u16 max_tonemap_size;
	u16 max_oetf_size;
	u16 max_degamma_size;
	u16 max_gamma_size;
	u16 cgm_lut_size; /* for 3D lut */
	u16 cgm_ex_lut_size; /* for roi 3D lut */

	u8 pre_eotf_bits; /* for FE EOTF module */
	u8 hdr_bits;
	u8 oetf_bits; /* for FE OETF module */
	u8 bld_cgm_bits; /* for blend EOTF, gamut map and OETF modules */
	u8 pre_degamma_bits; /* degamma in bits */
	u8 degamma_bits; /* degamma out bits */
	u8 cgm_lut_bits;
	u8 gamma_bits;
	u8 blur_coef_bits;
	u8 intr_dest; /*bit0 for NS, bit1 for TZ, bit2 for GSA, bit3 for AOC*/

	u32 std_color_lut : 1;
	u32 multi_roi : 1;
	u32 pipe_sync : 1;
	u32 mmu_prefetch : 1;
	u32 panel_sync : 1;
	/* cap_dec ===>
	 *  (1 << DRM_FORMAT_MOD_VS_EGT_TYPE_COMPRESSED) means support dec400
	 *  (1 << DRM_FORMAT_MOD_VS_EGT_TYPE_PVRIC) means support pvric
	 *  (1 << DRM_FORMAT_MOD_VS_EGT_TYPE_DECNANO) means support DECNANO
	 *  (1 << DRM_FORMAT_MOD_VS_EGT_TYPE_ETC2) means support ETC2
	 */
	u32 cap_dec;
	u8 roi_y_gap;

	u8 vrr : 1;
	u8 crc_roi : 1;

	u16 dma_sram_alignment; /* DMA sram pool buffer line alignment (Byte) */
	u8 dma_sram_extra_buffer : 1;
	u8 dma_sram_unit_size;

	u8 linear_yuv_rotation : 1;
	u8 any_resolution : 1;
};

enum check_format_type {
	SRC,
	ROI,
	SCALER,
};

struct format_limit_info {
	enum check_format_type type;
	u32 format;
	u8 width_align;
	u8 height_align;
	u16 min_width;
	u16 max_width;
	u16 min_height;
	u16 max_height;
	u16 address_align;
	u16 u_address_align;
	u16 v_address_align;
	u16 stride_align;
	u16 u_stride_align;
	u16 v_stride_align;
	u8 roi_offset_x_align;
	u8 roi_offset_y_align;
};

enum color_format_type {
	FORMAT_RGB888,
	FORMAT_RGB888_P, /* RGB888 planner */
	FORMAT_ARGB,
	FORMAT_YUV420,
	FORMAT_YUV422,
	FORMAT_ARGB16161616,
	FORMAT_ARGB_TILE_16X4,
	FORMAT_YUV_I010,
	FORMAT_YUV_YV12,
	FORMAT_NV12_TILE_32X8_A,
	FORMAT_LUMA_8 = 10,
	FORMAT_LUMA_10,
	/* PVRIC */
	FORMAT_ARGB_PV,
	FORMAT_YUV420_8BIT_PV,
	FORMAT_YUV420_10BIT_PV,
	FORMAT_ARGB16161616_PV,
	/* DEC */
	FORMAT_ARGB_DEC,
	FORMAT_ARGB_TILE_8X8_SPT_X_DEC,  /* tile 8x8 supertile_x */
	FORMAT_ARGB16161616_DEC,
	FROMAT_NV12_TILE_32X8_SP8X8_DEC, /* tile 32x8 yuvsp8x8 */
	FROMAT_P010_TILE_16X8_SP8X8_DEC = 20,
	FORMAT_YUV420_8BIT_DEC,
	FORMAT_YUV420_10BIT_DEC,
	FORMAT_YUV422_8BIT_DEC,
	FORMAT_YUV422_10BIT_DEC,
	FORMAT_INVALID,
};

#endif /* __VS_TYPE_H__ */
