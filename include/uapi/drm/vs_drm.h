/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (C) 2020 VeriSilicon Holdings Co., Ltd.
 */

#ifndef __VS_DRM_H__
#define __VS_DRM_H__

#include <drm/drm.h>
#include <linux/types.h>

/* Alignment with a power of two value. */
#define VS_ALIGN(n, align) (((n) + ((align)-1)) & ~((align)-1))

#define VS_ENABLE_CMD_LIST 0

/* FilterBlt information. */
#define VS_MAXKERNELSIZE 9
#define VS_SUBPIXELINDEXBITS 5

#define VS_SUBPIXELCOUNT (1 << VS_SUBPIXELINDEXBITS)

#define VS_SUBPIXELLOADCOUNT (VS_SUBPIXELCOUNT / 2 + 1)

#define VS_MAX_Y2R_COEF_NUM 15
#define VS_MAX_R2Y_COEF_NUM 15
#define VS_MAX_GAMUT_COEF_NUM 12

#define VS_MAX_LUT_SEG_CNT 10
#define VS_MAX_LUT_ENTRY_CNT 129
#define VS_MAX_PRIOR_3DLUT_SIZE 4913
#define VS_MAX_ROI_3DLUT_SIZE 729
#define VS_MAX_1D_LUT_ENTRY_CNT 129
#define VS_MAX_GAMMA_ENTRY_CNT 257
#define VS_MAX_GAMMA_EX_ENTRY_CNT 300
#define VS_MAX_COLOR_BAR_NUM 16

#define VS_LTM_LUMA_COEF_NUM 5
#define VS_LTM_FREQ_COEF_NUM 9
#define VS_LTM_FREQ_NORM_FRAC_BIT 18
#define VS_LTM_AFFINE_LUT_NUM 1152 /* 12x12x8 */
#define VS_LTM_AFFINE_SLICE_NUM 2
#define VS_LTM_AFFINE_OUT_SCALE_SIZE 17
#define VS_LTM_TONE_ADJ_COEF_NUM 129
#define VS_LTM_ALPHA_GAIN_SIZE 121
#define VS_LTM_ALPHA_LUMA_SIZE 129
#define VS_LTM_SATU_CTRL_SIZE 257
#define VS_LTM_XGAMMA_COEF_NUM 65
#define VS_LTM_DITHER_COEF_NUM 3
#define VS_LTM_CD_COEF_NUM 4
#define VS_LTM_CD_THRESH_NUM 4
#define VS_LTM_CD_SLOPE_NUM 2
#define VS_LTM_CD_RESULT_NUM 256
#define VS_LTM_HIST_POS_NUM 2
#define VS_LTM_HIST_SCALE_NUM 2
#define VS_LTM_HIST_RESULT_NUM 9216 /* 12x12x64 */
#define VS_HIST_RESULT_BIN_CNT 256

#define VS_SHARPNESS_CSC_COEF_NUM 9
#define VS_SHARPNESS_CSC_OFFSET_NUM 3
#define VS_SHARPNESS_LUMA_GAIN_LUT_ENTRY_NUM 9
#define VS_SHARPNESS_CA_MODE_NUM 3
#define VS_SHARPNESS_CA_PARAM_NUM 7
#define VS_SHARPNESS_LPF_COEF_NUM 4
#define VS_SHARPNESS_LPF_NOISE_LUT_NUM 9
#define VS_SHARPNESS_LPF_CURVE_LUT_NUM 13
#define VS_SHARPNESS_LPF_NORM_BPP 16

#define VS_RANDOM_DITHER_SEED_NUM 8

#define VS_SCALE_HORI_COEF_NUM 77
#define VS_SCALE_VERT_COEF_NUM 77

#define VS_MAX_ROI_CNT 2

#define VS_MAX_EXT_LAYER_CNT 3

#define VS_BLEND_ALPHA_OPAQUE 0xff

/* Max blur ROI width is 1440, min blur width is 100 */
#define VS_BLUR_COEF_NUM 4
#define VS_BLUR_COEF_SUM_MIN 1
#define VS_BLUR_COEF_SUM_MAX 64
#define VS_BLUR_NORM_BPP 16
#define VS_BLUR_ROI_MAX_WIDTH 1440
#define VS_BLUR_ROI_MIN_WIDTH 100

/* brightness: Max target gain is 2^10, max brightness value is 2^14 - 1 */
#define VS_MAX_TARGET_GAIN_VALUE 1024
#define VS_MAX_BRIGHTNESS_VALUE 16383

#define DEGAMMA_SIZE 260

/* sr2000: nr coef number is 25, nllcoef number is 17, ssr3 coef number is 268 */
#define VS_NR_COEF_NUM 25
#define VS_NR_NULL_COEF_NUM 17
#define VS_SSR3_COEF_NUM 268

enum drm_vs_degamma_mode {
	VS_DEGAMMA_BT709 = 0,
	VS_DEGAMMA_BT2020 = 1,
	VS_DEGAMMA_USR = 2,
};

struct drm_vs_degamma_config {
	enum drm_vs_degamma_mode mode;
	__u16 r[DEGAMMA_SIZE];
	__u16 g[DEGAMMA_SIZE];
	__u16 b[DEGAMMA_SIZE];
};

enum drm_vs_sync_dc_mode {
	VS_SINGLE_DC = 0,
	VS_MULTI_DC_PRIMARY = 1,
	VS_MULTI_DC_SECONDARY = 2,
};

enum drm_vs_mmu_prefetch_mode {
	VS_MMU_PREFETCH_DISABLE = 0,
	VS_MMU_PREFETCH_ENABLE = 1,
};

enum drm_vs_dma_mode {
	/* read full image */
	VS_DMA_NORMAL = 0,
	/* read one ROI region in the image */
	VS_DMA_ONE_ROI = 1,
	/* read two ROI regions in the image */
	VS_DMA_TWO_ROI = 2,
	/* skip the ROI region in the image */
	VS_DMA_SKIP_ROI = 3,
	/* for extend layer mode
	 * read full image0 and image1, don't.
	 */
	VS_DMA_EXT_LAYER = 4,
	/* for extend layer mode
	 * read ROI region from image0 and
	 * read exrended ROI region from image1.
	 */
	VS_DMA_EXT_LAYER_EX = 5,
};

enum drm_vs_line_padding_mode {
	/*ratio 1:1*/
	VS_DMA_LINE_PADDING_1TO1 = 0,
	/*ratio 2:1*/
	VS_DMA_LINE_PADDING_2TO1 = 1,
	/*ratio 3:1*/
	VS_DMA_LINE_PADDING_3TO1 = 2,
	/*ratio 3:2*/
	VS_DMA_LINE_PADDING_3TO2 = 3,
	/*ratio 4:1*/
	VS_DMA_LINE_PADDING_4TO1 = 4,
	/*ratio 4:3*/
	VS_DMA_LINE_PADDING_4TO3 = 5,
	/*ratio 5:2*/
	VS_DMA_LINE_PADDING_5TO2 = 6,
	/*ratio 5:3*/
	VS_DMA_LINE_PADDING_5TO3 = 7,
	/*ratio 8:5*/
	VS_DMA_LINE_PADDING_8TO5 = 8,
};

enum drm_vs_sbs_mode {
	VS_SBS_LEFT = 0,
	VS_SBS_RIGHT = 1,
	VS_SBS_SPLIT = 2,
	VS_SBS_RESERVED = 3,
};

enum drm_vs_alpha_mode {
	VS_ALPHA_NORMAL = 0,
	VS_ALPHA_INVERSE = 1,
};

enum drm_vs_galpha_mode {
	VS_GALPHA_NORMAL = 0,
	VS_GALPHA_GLOBAL = 1,
	VS_GALPHA_MULTIPLE = 2,
};

enum drm_vs_ltm_luma_mode {
	VS_LTM_LUMA_GRAY = 0,
	VS_LTM_LUMA_LIGHTNESS = 1,
	VS_LTM_LUMA_MIXED = 2,
};

enum drm_vs_blend_mode {
	VS_BLD_CLR = 0,
	VS_BLD_SRC = 1,
	VS_BLD_DST = 2,
	VS_BLD_SRC_OVR = 3,
	VS_BLD_DST_OVR = 4,
	VS_BLD_SRC_IN = 5,
	VS_BLD_DST_IN = 6,
	VS_BLD_SRC_OUT = 7,
	VS_BLD_DST_OUT = 8,
	VS_BLD_SRC_ATOP = 9,
	VS_BLD_DST_ATOP = 10,
	VS_BLD_XOR = 11,
	VS_BLD_PLUS = 12,
	VS_BLD_BLD = 13,
	VS_BLD_UDEF = 14,
};

enum drm_vs_wb_point {
	VS_WB_DISP_OUT = 0,
	VS_WB_DISP_IN = 1,
	VS_WB_DISP_CC = 2,
	VS_WB_OFIFO_IN = 3,
	VS_WB_OFIFO_OUT = 4,
	VS_WB_POS_CNT = 5,
};

enum drm_vs_eotf_mode {
	VS_EO_ProgConf = 1,
	VS_EO_PQ = 2,
	VS_EO_HLG = 3,
	VS_EO_170M = 4,
	VS_EO_SRGB = 5,
	VS_EO_DeGamma2_2 = 6,
};

enum drm_vs_oetf_mode {
	VS_OE_ProgConf = 1,
	VS_OE_PQ = 2,
	VS_OE_HLG = 3,
	VS_OE_170M = 4,
	VS_OE_SRGB = 5,
	VS_OE_ReGamma2_2 = 6,
};

enum drm_vs_tonemapping_mode {
	VS_TM_HDR10 = 1,
	VS_TM_HLG = 2,
	VS_TM_ProgConf = 3,
	VS_TM_Reinhard = 4,
	VS_InvTM_Reinhard = 5,
	VS_TM_ProgCurve = 6,
};

enum drm_vs_gamut_mode {
	VS_GAMUT_709_TO_2020 = 0,
	VS_GAMUT_2020_TO_709 = 1,
	VS_GAMUT_2020_TO_DCIP3 = 2,
	VS_GAMUT_DCIP3_TO_2020 = 3,
	VS_GAMUT_DCIP3_TO_SRGB = 4,
	VS_GAMUT_SRGB_TO_DCIP3 = 5,
	VS_GAMUT_USER_DEF = 6,
};

enum drm_vs_csc_mode {
	VS_CSC_CM_USR,
	VS_CSC_CM_L2L,
	VS_CSC_CM_L2F,
	VS_CSC_CM_F2L,
	VS_CSC_CM_F2F,
};

enum drm_vs_csc_gamut {
	VS_CSC_CG_601,
	VS_CSC_CG_709,
	VS_CSC_CG_2020,
	VS_CSC_CG_P3,
	VS_CSC_CG_SRGB,
};

enum drm_vs_calcu_mode {
	VS_CALC_LNR_COMBINE = 0,
	VS_CALC_MAX = 1,
	VS_CALC_MIXED = 2,
};

enum drm_vs_data_extend_mode {
	VS_DATA_EXT_STD = 0,
	VS_DATA_EXT_MSB = 1,
	VS_DATA_EXT_RANDOM = 2,
};

enum drm_vs_data_trunc_mode {
	VS_DATA_TRUNCATE = 0,
	VS_DATA_ROUNDING = 1,
};

enum drm_vs_dth_frm_idx {
	VS_DTH_FRM_IDX_NONE = 0,
	VS_DTH_FRM_IDX_SW = 1,
	VS_DTH_FRM_IDX_HW = 2,
};

enum drm_vs_dth_frm_mode {
	VS_DTH_FRM_4 = 4,
	VS_DTH_FRM_8 = 8,
	VS_DTH_FRM_16 = 16,
};

enum drm_vs_pattern_mode {
	VS_PURE_COLOR = 0,
	VS_COLOR_BAR_H = 1,
	VS_COLOR_BAR_V = 2,
	VS_RMAP_H = 3,
	VS_RMAP_V = 4,
	VS_BLACK_WHITE_H = 5,
	VS_BLACK_WHITE_V = 6,
	VS_BLACK_WHITE_SQR = 7,
	VS_BORDER_PATRN = 8,
	VS_CURSOR_PATRN = 9,
};

enum drm_vs_disp_tp_pos {
	VS_DISP_TP_BLD = 0,
	VS_DISP_TP_POST_PROC = 1,
	VS_DISP_TP_OFIFO = 2,
};

enum drm_vs_plane_crc_pos {
	VS_PLANE_CRC_DFC = 0,
	VS_PLANE_CRC_HDR = 1,
};

enum drm_vs_disp_crc_pos {
	VS_DISP_CRC_BLD = 0,
	VS_DISP_POST_PROC = 1,
	VS_DISP_CRC_OFIFO_IN = 2,
	VS_DISP_CRC_OFIFO_OUT = 3,
	VS_DISP_CRC_WB = 4,
};

enum drm_vs_reset_mode {
	VS_RESET = 0,
	VS_FE0_RESET = 1,
	VS_FE1_RESET = 2,
	VS_BE_RESET = 3,
};

enum drm_vs_sw_reset_mode {
	VS_CLE_SW_RESET = 0,
};

enum drm_vs_feature_cap_type {
	VS_FEATURE_CAP_FBC = 0,
	VS_FEATURE_CAP_MAX_BLEND_LAYER,
	VS_FEATURE_CAP_CURSOR_WIDTH,
	VS_FEATURE_CAP_CURSOR_HEIGHT,
	VS_FEATURE_CAP_LINEAR_YUV_ROTATION,
	VS_FEATURE_CAP_ANY_RESOLUTION,
	VS_FEATURE_CAP_MAX_WIDTH,
	VS_FEATURE_CAP_MAX_HEIGHT,
	VS_FEATURE_CAP_USE_VCMD,
	VS_FEATURE_CAP_VCMD_CMDBUF_REMAINING,
};

enum drm_vs_sharpness_ink_mode {
	VS_SHARPNESS_INK_DEFAULT = 0x0,
	VS_SHARPNESS_INK_G0 = 0x1,
	VS_SHARPNESS_INK_G1 = 0x2,
	VS_SHARPNESS_INK_G2 = 0x3,
	VS_SHARPNESS_INK_L0 = 0x4,
	VS_SHARPNESS_INK_L1 = 0x5,
	VS_SHARPNESS_INK_L2 = 0x6,
	VS_SHARPNESS_INK_ADAPT = 0x7,
	VS_SHARPNESS_INK_V0 = 0x8,
	VS_SHARPNESS_INK_V1 = 0x9,
	VS_SHARPNESS_INK_V2 = 0xA,
	VS_SHARPNESS_INK_LUMA = 0xB,
};

enum drm_vs_brightness_cal_mode {
	VS_BRIGHTNESS_CAL_MODE_WEIGHT = 0,
	VS_BRIGHTNESS_CAL_MODE_MAX = 1,
	VS_BRIGHTNESS_CAL_MODE_COUNT = 2,
};

/* Brightness Compensation ROI */
enum drm_vs_brightness_roi_type {
	VS_BRIGHTNESS_ROI0 = 0,
	VS_BRIGHTNESS_ROI1 = 1,
};

enum drm_vs_gem_query_type {
	VS_GEM_QUERY_HANDLE = 0,
};

enum drm_vs_mask_blend_type {
	VS_MASK_BLD_NORM,
	VS_MASK_BLD_INV,
	VS_MASK_BLD_COUNT,
};

enum drm_vs_rcd_bg_type {
	VS_RCD_BG_PNL,
	VS_RCD_BG_ROI,
	VS_RCD_BG_COUNT,
};

enum drm_vs_rcd_roi_type {
	VS_RCD_ROI_TOP,
	VS_RCD_ROI_BTM,
	VS_RCD_ROI_COUNT,
};

enum drm_vs_dec_pos {
	VS_DEC_BRT = 0,
	VS_DEC_BLUR,
	VS_DEC_RCD,
	VS_DEC_COUNT,
};

/*
histogram collects the image characteristics for SW to perform various related features.
There are 4 independent programmable histograms: VS_HIST_IDX_0 ~ VS_HIST_IDX_3
VS_HIST_IDX_RGB is for rgbHistogram
*/
enum drm_vs_hist_idx {
	VS_HIST_IDX_0,
	VS_HIST_IDX_1,
	VS_HIST_IDX_2,
	VS_HIST_IDX_3,
	VS_HIST_IDX_RGB,
	VS_HIST_IDX_COUNT,
};

enum drm_vs_hist_pos {
	VS_HIST_POS_SCALE,
	VS_HIST_POS_RCD,
	VS_HIST_POS_POST,
};

enum drm_vs_hist_bin_mode {
	VS_HIST_BIN_MAX,
	VS_HIST_BIN_WEIGHT,
	VS_HIST_BIN_RVALUE,
	VS_HIST_BIN_GVALUE,
	VS_HIST_BIN_BVALUE,
};

enum drm_vs_hist_out_mode {
	VS_HIST_BY_APB,
	VS_HIST_BY_WDMA,
};

enum dc_hw_sram_unit_size {
	SRAM_UNIT_SIZE_64KB,
	SRAM_UNIT_SIZE_32KB,
};

enum drm_vs_nr_mode {
	VS_NR_WEAK = 0,
	VS_NR_STRONG = 1,
};

enum drm_vs_ssr3_mode {
	VS_SSR3_STRONG_UPS = 0,
	VS_SSR3_NATURE = 1,
	VS_SSR3_TV1 = 2,
	VS_SSR3_TV2 = 3,
	VS_SSR3_TV3 = 4,
	VS_SSR3_DESK = 5,
	VS_SSR3_GAME = 6,
};

enum drm_vs_ctx_ioctl_type {
	VS_CTX_CREATE = 0,
	VS_CTX_FREE = 1,
	VS_CTX_QUERY = 2,
	VS_CTX_UPDATE_LTM = 3,
};

enum drm_vs_filter_type {
	/*for dc9x00 */
	VS_H9_V5 = 0,
	/*for dc8200 */
	VS_H5_V3 = 1,
	VS_H3_V3 = 2,
};

enum drm_vs_dc_exception_type {
	VS_DC_FE0_PVRIC_DECODE_ERROR = 0,
	VS_DC_FE0_AXI_HANG,
	VS_DC_FE0_AXI_BUS_ERROR,
	VS_DC_FE0_APB_HANG,
	VS_DC_FE1_PVRIC_DECODE_ERROR,
	VS_DC_FE1_AXI_HANG, /* 5 */
	VS_DC_FE1_AXI_BUS_ERROR,
	VS_DC_FE1_APB_HANG,
	VS_DC_BE_UNDERRUN,
	VS_DC_BE_DATALOST,
	VS_DC_BE_APB_HANG, /* 10 */
	VS_DC_BE_AXI_BUS_ERROR,
	VS_DC_BE_AXI_RD_BUS_HANG,
	VS_DC_BE_AXI_WR_BUS_HANG,
	VS_DC_BE_AXI_WRITE_BUS_ERROR,
	VS_DC_BE_AXI_WRITE_BUS_HANG, /* 15 */
	VS_DC_BE_BLEND_WRITE_BACK_UNDERFLOW,
	VS_DC_BE_OUTIF_WRITE_BACK_UNDERFLOW,
	VS_DC_EXCEPTION_COUNT,
};

struct drm_vs_alpha_data_extend {
	__u8 enable;
	__u32 alpha_extend_value; /* alpha3[31:24], alpha2[23:16], alpha1[15:8], alpha0[7:0] */
};

struct drm_vs_data_extend {
	enum drm_vs_data_extend_mode data_extend_mode;
	struct drm_vs_alpha_data_extend alpha_data_extend;
};

struct drm_vs_splice_config {
	__u8 crtc_id;
	__u8 crtc_id_ex;
	__u8 crtc_ofifo_id;
	__u8 crtc_ofifo_id_ex;
};

struct drm_vs_splice_mode {
	__u8 splice0_enable;
	__u8 splice0_crtc_mask; /* crtc id mask */
	__u8 splice0_output_intf;
	__u8 splice1_enable;
	__u8 splice1_crtc_mask; /* crtc id mask */
	__u8 splice1_output_intf;
	__u16 src_panel_width0;
	__u16 src_panel_width1;
};

struct drm_vs_dp_sync {
	__u8 dp_sync_crtc_mask; /* crtc id mask */
};

enum drm_vs_free_sync_type {
	VS_FREE_SYNC_CONFIG,
	VS_FREE_SYNC_FINISH,
	VS_FREE_SYNC_CONFIG_FINISH,
};

struct drm_vs_free_sync_mode {
	__u16 free_sync_max_delay; /* max delay lines number */
	__u8 free_sync_finish;
};

struct drm_vs_free_sync {
	enum drm_vs_free_sync_type type;
	struct drm_vs_free_sync_mode mode;
};

/* Sharpness */
struct drm_vs_sharpness {
	__u8 enable;
	enum drm_vs_sharpness_ink_mode ink_mode;
};

struct drm_vs_sharpness_csc {
	int y2r_coef[VS_SHARPNESS_CSC_COEF_NUM];
	int r2y_coef[VS_SHARPNESS_CSC_COEF_NUM];
	int y2r_offset[VS_SHARPNESS_CSC_OFFSET_NUM];
	int r2y_offset[VS_SHARPNESS_CSC_OFFSET_NUM];
};

struct drm_vs_sharpness_luma_gain {
	int lut[VS_SHARPNESS_LUMA_GAIN_LUT_ENTRY_NUM];
};

struct drm_vs_sharpness_lpf {
	__u32 lpf0_coef[VS_SHARPNESS_LPF_COEF_NUM];
	__u32 lpf1_coef[VS_SHARPNESS_LPF_COEF_NUM];
	__u32 lpf2_coef[VS_SHARPNESS_LPF_COEF_NUM];
	__u32 lpf0_norm;
	__u32 lpf1_norm;
	__u32 lpf2_norm;
};

struct drm_vs_sharpness_lpf_noise {
	__u32 lut0[VS_SHARPNESS_LPF_NOISE_LUT_NUM];
	__u32 lut1[VS_SHARPNESS_LPF_NOISE_LUT_NUM];
	__u32 lut2[VS_SHARPNESS_LPF_NOISE_LUT_NUM];
	__u32 luma_strength0;
	__u32 luma_strength1;
	__u32 luma_strength2;
};

struct drm_vs_sharpness_lpf_curve {
	__u32 lut0[VS_SHARPNESS_LPF_CURVE_LUT_NUM];
	__u32 lut1[VS_SHARPNESS_LPF_CURVE_LUT_NUM];
	__u32 lut2[VS_SHARPNESS_LPF_CURVE_LUT_NUM];
	__u32 master_gain;
};

struct drm_vs_sharpness_color_adaptive_mode {
	__u8 enable;
	__u32 gain;
	__u32 theta_center;
	__u32 theta_range;
	__u32 theta_slope;
	__u32 radius_center;
	__u32 radius_range;
	__u32 radius_slope;
};

struct drm_vs_sharpness_color_adaptive {
	struct drm_vs_sharpness_color_adaptive_mode mode[VS_SHARPNESS_CA_MODE_NUM];
};

struct drm_vs_sharpness_color_boost {
	__u32 pos_gain;
	__u32 neg_gain;
	__u32 y_offset;
};

struct drm_vs_sharpness_soft_clip {
	__u32 pos_offset;
	__u32 neg_offset;
	__u32 pos_wet;
	__u32 neg_wet;
};

/* RGB table */
struct drm_vs_sharpness_dither {
	__u32 table_low[3];
	__u32 table_high[3];
};

enum drm_vs_ds_mode {
	VS_DS_DROP = 0,
	VS_DS_AVERAGE = 1,
	VS_DS_FILTER = 2,
};

struct drm_vs_rect {
	__u16 x;
	__u16 y;
	__u16 w;
	__u16 h;
};

struct drm_vs_color {
	__u32 a;
	__u32 r;
	__u32 g;
	__u32 b;
};

struct drm_vs_spliter {
	__u32 left_x;
	__u32 left_w;
	__u32 right_x;
	__u32 right_w;
	__u32 src_w;
};

struct drm_vs_panel_crop {
	struct drm_vs_rect crop_rect;
	__u16 panel_src_width;
	__u16 panel_src_height;
};

struct drm_vs_colorkey {
	__u32 colorkey;
	__u32 colorkey_high;
	__u8 transparency;
};

struct drm_vs_watermark {
	__u32 watermark;
	__u8 qos_low;
	__u8 qos_high;
};

struct drm_vs_dma {
	enum drm_vs_dma_mode mode;
	/* in_rect[0] is available under the DMA mode:
	 *	   VS_DMA_ONE_ROI: the ROI region rectangle.
	 *	   VS_DMA_TWO_ROI: the first ROI region rectangle.
	 *	   VS_DMA_SKIP_ROI: the skip ROI region rectangle.
	 *	   VS_DMA_EXT_LAYER_EX: the ROI region rectangle of first image.
	 * in_rect[1] is avilable under the DMA mode:
	 *	   VS_DMA_TWO_ROI: the seconf ROI region rectangle.
	 *	   VS_DMA_EXT_LAYER_EX: the ROI region rectangle of second image.
	 */
	struct drm_vs_rect in_rect[VS_MAX_ROI_CNT];
	/* out_rect[0] is available under the DMA mode:
	 *	   VS_DMA_ONE_ROI: specify the ROI out region.
	 *	   VS_DMA_TWO_ROI: specify the first ROI out region.
	 *	   VS_DMA_SKIP_ROI: specify skip ROI out region.
	 *	   VS_DMA_EXT_LAYER: specify the first image out region.
	 *	   VS_DMA_EXT_LAYER_EX: specify the ROI out region of first image.
	 * out_rect[1] is avilable under the DMA mode:
	 *	   VS_DMA_TWO_ROI: specify the seconf ROI out region.
	 *	   VS_DMA_EXT_LAYER: specify the second image out region.
	 *	   VS_DMA_EXT_LAYER_EX: specify the ROI out region of second image.
	 */
	struct drm_vs_rect out_rect[VS_MAX_ROI_CNT];
};

struct drm_vs_ex_layer {
	__u8 num;
	__u32 fb_id[VS_MAX_EXT_LAYER_CNT];
	int fd;
	struct drm_vs_rect out_rect[VS_MAX_EXT_LAYER_CNT];
	__u32 fourcc;
	__u64 modifier;
	struct drm_vs_rect crop_rect[VS_MAX_EXT_LAYER_CNT];
};

struct drm_vs_line_padding {
	enum drm_vs_line_padding_mode mode;
	struct drm_vs_color color;
};

struct drm_vs_sbs {
	enum drm_vs_sbs_mode mode;
	/* available under the VS_SBS_SPLIT mode, side-by-side left width. */
	__u16 left_w;
	/* available under the VS_SBS_SPLIT mode, side-by-side right start X. */
	__u16 right_x;
	/* available under the VS_SBS_SPLIT mode, side-by-side right width. */
	__u16 right_w;
};

struct drm_vs_y2r_config {
	enum drm_vs_csc_mode mode;
	enum drm_vs_csc_gamut gamut;
	__s32 coef[VS_MAX_Y2R_COEF_NUM];
};

struct drm_vs_r2y_config {
	enum drm_vs_csc_mode mode;
	enum drm_vs_csc_gamut gamut;
	__s32 coef[VS_MAX_R2Y_COEF_NUM];
	/* For debug, the output bus format.
	 *     Usually the output bus format info from encoder.
	 *     In our driver, the default output bus format is MEDIA_BUS_FMT_RGB888_1X24
	 *     For the convernience of debugging, adding an output bus format setting here for debugging the
	 *     writeback data.
	 */
	__u32 output_bus_format;
};

struct drm_vs_scale_config {
	__u16 src_w;
	__u16 src_h;
	__u16 dst_w;
	__u16 dst_h;
	__u32 factor_x;
	__u32 factor_y;
	__u32 initial_offsetx;
	__u32 initial_offsety;
	__u32 coef_h[VS_SCALE_HORI_COEF_NUM];
	__u32 coef_v[VS_SCALE_VERT_COEF_NUM];
	enum drm_vs_filter_type filter;
};

struct drm_vs_ds_config {
	enum drm_vs_ds_mode h_mode;
	enum drm_vs_ds_mode v_mode;
};

struct drm_vs_roi_lut_config {
	struct drm_vs_rect rect;
	struct drm_vs_color data[VS_MAX_ROI_3DLUT_SIZE];
};

struct drm_vs_gamut_map {
	enum drm_vs_gamut_mode mode;
	__s32 coef[VS_MAX_GAMUT_COEF_NUM];
};

/*need to refine*/
struct drm_vs_data_block {
	__u32 size; /* total size of data block buffer */
	__u64 logical;
};

struct drm_vs_xstep_lut {
	__u32 seg_cnt;
	__u32 seg_point[VS_MAX_LUT_SEG_CNT - 1];
	__u32 seg_step[VS_MAX_LUT_SEG_CNT];
	__u32 entry_cnt;
	__u32 data[VS_MAX_LUT_ENTRY_CNT];
};

struct drm_vs_gamma_lut {
	__u32 seg_cnt;
	__u32 seg_point[VS_MAX_LUT_SEG_CNT - 1];
	__u32 seg_step[VS_MAX_LUT_SEG_CNT];
	__u32 entry_cnt;
	struct drm_vs_color data[VS_MAX_GAMMA_ENTRY_CNT];
	/*SR: use gamma soft-alog, need refine*/
	struct drm_vs_color seg_cnt_sr;
	struct drm_vs_color seg_point_sr[VS_MAX_LUT_SEG_CNT - 1];
	struct drm_vs_color seg_step_sr[VS_MAX_LUT_SEG_CNT];
	struct drm_vs_color entry_cnt_sr;
};

struct drm_vs_lut {
	__u32 entry_cnt;
	__u32 seg_point[VS_MAX_LUT_ENTRY_CNT - 1];
	__u32 data[VS_MAX_LUT_ENTRY_CNT];
};

struct drm_vs_blend_alpha {
	/* src alpha pre process */
	enum drm_vs_alpha_mode sam;
	enum drm_vs_galpha_mode sgam;
	__u32 sga;
	__u32 saa;

	/* dst alpha pre process */
	enum drm_vs_alpha_mode dam;
	enum drm_vs_galpha_mode dgam;
	__u32 dga;
	__u32 daa;
};

struct drm_vs_1d_lut {
	__u8 enable;
	__u32 entry_cnt;
	__u32 data[VS_MAX_1D_LUT_ENTRY_CNT];
};

struct drm_vs_ltm_xgamma {
	__u8 enable;
	__u32 coef[VS_LTM_XGAMMA_COEF_NUM];
};

struct drm_vs_ltm_luma {
	__u8 enable;
	enum drm_vs_ltm_luma_mode mode;
	__u16 coef[VS_LTM_LUMA_COEF_NUM];
};

struct drm_vs_ltm_freq_decomp {
	__u8 decomp_enable;
	__u16 coef[VS_LTM_FREQ_COEF_NUM];
	__u32 norm;
};

struct drm_vs_ltm_grid {
	__u8 enable;
	__u16 width;
	__u16 height;
	__u16 depth;
};

struct drm_vs_ltm_af_filter {
	__u8 enable;
	__u16 weight;
	__u32 slope[VS_LTM_AFFINE_LUT_NUM];
	__u32 bias[VS_LTM_AFFINE_LUT_NUM];
};

struct drm_vs_ltm_af_slice {
	__u8 enable;
	__u16 start_pos[VS_LTM_AFFINE_SLICE_NUM];
	__u16 scale[VS_LTM_AFFINE_SLICE_NUM];
	__u16 scale_half[VS_LTM_AFFINE_SLICE_NUM];
};

struct drm_vs_ltm_af_trans {
	__u8 enable;
	__u8 slope_bit;
	__u8 bias_bit;
	__u16 scale[VS_LTM_AFFINE_OUT_SCALE_SIZE];
};

struct drm_vs_ltm_tone_adj {
	__u8 enable;
	__u8 luma_from;
	__u32 entry_cnt;
	__u32 data[VS_MAX_1D_LUT_ENTRY_CNT];
};

struct drm_vs_ltm_color {
	__u8 enable;
	__u8 satu_ctrl;
	__u16 luma_thresh;
	__u16 gain[VS_LTM_ALPHA_GAIN_SIZE];
	__u16 luma[VS_LTM_ALPHA_LUMA_SIZE];
	__u16 satu[VS_LTM_SATU_CTRL_SIZE];
};

struct drm_vs_ltm_dither {
	__u8 dither_enable;
	__u32 table_low[VS_LTM_DITHER_COEF_NUM];
	__u32 table_high[VS_LTM_DITHER_COEF_NUM];
};

struct drm_vs_ltm_luma_ave {
	__u8 enable;
	__u16 margin_x;
	__u16 margin_y;
	__u16 pixel_norm;
	__u16 ave;
};

struct drm_vs_ltm_cd_set {
	__u8 enable;
	__u8 overlap;
	__u32 min_wgt;
	__u32 filt_norm;
	__u32 coef[VS_LTM_CD_COEF_NUM];
	__u32 thresh[VS_LTM_CD_THRESH_NUM];
	__u32 slope[VS_LTM_CD_SLOPE_NUM];
};

struct drm_vs_ltm_cd_get {
	__u32 result[VS_LTM_CD_RESULT_NUM];
};

struct drm_vs_ltm_hist_set {
	__u8 enable;
	__u8 overlap;
	__u32 grid_depth;
	__u32 start_pos[VS_LTM_HIST_POS_NUM];
	__u32 grid_scale[VS_LTM_HIST_SCALE_NUM];
};

struct drm_vs_ltm_hist_get {
	__u8 enable;
	__u32 fd;
	__u32 hist_bo_handle;
	__u32 result[VS_LTM_HIST_RESULT_NUM];
};

struct drm_vs_ltm_ds {
	__u8 enable;
	__u32 h_norm;
	__u32 v_norm;
	__u32 crop_l;
	__u32 crop_r;
	__u32 crop_t;
	__u32 crop_b;
	struct drm_vs_rect output;
};

struct drm_vs_ltm {
	struct drm_vs_ltm_xgamma ltm_degamma;
	struct drm_vs_ltm_xgamma ltm_gamma;
	struct drm_vs_ltm_luma ltm_luma;
	struct drm_vs_ltm_freq_decomp freq_decomp;
	struct drm_vs_1d_lut luma_adj;
	struct drm_vs_ltm_grid grid_size;
	struct drm_vs_ltm_af_filter af_filter;
	struct drm_vs_ltm_af_slice af_slice;
	struct drm_vs_ltm_af_trans af_trans;
	struct drm_vs_ltm_tone_adj tone_adj;
	struct drm_vs_ltm_color ltm_color;
	struct drm_vs_ltm_dither ltm_dither;
	struct drm_vs_ltm_luma_ave ltm_luma_set;
	struct drm_vs_ltm_cd_set ltm_cd_set;
	struct drm_vs_ltm_hist_set ltm_hist_set;
	struct drm_vs_ltm_ds ltm_ds;
	struct drm_vs_ltm_hist_get ltm_hist_get;
};

struct drm_vs_gtm {
	struct drm_vs_ltm_xgamma gtm_degamma;
	struct drm_vs_ltm_xgamma gtm_gamma;
	struct drm_vs_ltm_luma gtm_luma;
	struct drm_vs_ltm_tone_adj tone_adj;
	struct drm_vs_ltm_color gtm_color;
	struct drm_vs_ltm_dither gtm_dither;
	struct drm_vs_ltm_luma_ave gtm_luma_set;
	struct drm_vs_ltm_ds gtm_ds;
};

struct drm_vs_blend {
	enum drm_vs_blend_mode color_mode;
	enum drm_vs_blend_mode alpha_mode;
};

struct drm_vs_tone_map_y {
	enum drm_vs_calcu_mode y_mode;
	__u16 coef0;
	__u16 coef1;
	__u16 coef2;
	__u16 weight;
};

struct drm_vs_tone_map {
	struct drm_vs_tone_map_y pseudo_y;
	struct drm_vs_lut lut;
};

struct drm_vs_hdr_algo_programmable {
	__u8 mode;
	char *programmable_csv;
};

struct drm_vs_hdr_algo_tone_map {
	__u8 mode;
	__u8 y2r_gamut;
	char *programmable_csv;
	__u16 max_cll;
	__u16 max_dll;
	double ks;
	double kf;
	double bezier_p[17];
	int len_p;
};

struct drm_vs_hdr_algo_config {
	__u8 hdr_enable;
	__u8 de_multiply;
	__u8 eotf_enable;
	__u8 gamut_enable;
	__u8 tonemapping_enable;
	__u8 oetf_enable;
	struct drm_vs_hdr_algo_programmable eotf;
	struct drm_vs_hdr_algo_programmable gamut;
	struct drm_vs_hdr_algo_tone_map tonemap;
	struct drm_vs_hdr_algo_programmable oetf;
};

struct drm_vs_data_trunc {
	enum drm_vs_data_trunc_mode gamma_data_trunc;
	enum drm_vs_data_trunc_mode panel_data_trunc;
	enum drm_vs_data_trunc_mode blend_data_trunc;
	enum drm_vs_data_trunc_mode wb_data_trunc;
};

struct drm_vs_lut_config_ex {
	__u8 enable[3];
	struct drm_vs_rect rect[2];
	struct drm_vs_data_block data[3];
};

struct drm_vs_dither {
	enum drm_vs_dth_frm_idx index_type;
	__u8 sw_index;
	__u32 table_low[3];
	__u32 table_high[3];
	enum drm_vs_dth_frm_mode frm_mode;
};

struct drm_vs_random_dither_seed {
	__u8 hash_seed_x_enable;
	__u8 hash_seed_y_enable;
	__u8 permut_seed1_enable;
	__u8 permut_seed2_enable;
	__u32 hash_seed_x[VS_RANDOM_DITHER_SEED_NUM];
	__u32 hash_seed_y[VS_RANDOM_DITHER_SEED_NUM];
	__u32 permut_seed1[VS_RANDOM_DITHER_SEED_NUM];
	__u32 permut_seed2[VS_RANDOM_DITHER_SEED_NUM];
};

struct drm_vs_blender_dither {
	enum drm_vs_dth_frm_idx index_type;
	__u8 sw_index;
	__u8 noise;
	__u16 start_x;
	__u16 start_y;
	__u16 mask;
	struct drm_vs_random_dither_seed seed;
};

struct drm_vs_llv_dither {
	enum drm_vs_dth_frm_idx index_type;
	__u8 sw_index;
	__u16 start_x;
	__u16 start_y;
	__u16 mask;
	__u16 threshold;
	__u16 linear_threshold;
	struct drm_vs_random_dither_seed seed;
};

struct drm_vs_wb_dither {
	__u32 table_low[3];
	__u32 table_high[3];
	enum drm_vs_dth_frm_idx index_type;
	__u8 sw_index;
	enum drm_vs_dth_frm_mode frm_mode;
};

struct drm_vs_wb_spliter {
	struct drm_vs_rect split_rect0;
	struct drm_vs_rect split_rect1;
};

struct drm_vs_ccm {
	__s32 coef[9];
	__s32 offset[3];
};

struct drm_vs_blur {
	__u8 enable;
	struct drm_vs_rect roi;
	__u8 coef[3][VS_BLUR_COEF_NUM];
	__u32 norm[3];
	__u8 coef_num;
};

struct drm_vs_rcd_enable {
	__u8 enable;
	enum drm_vs_mask_blend_type type;
};

struct drm_vs_rcd_bg {
	__u32 pnl_color;
	__u8 roi_enable;
	__u32 roi_color;
	struct drm_vs_rect roi_rect;
	__u8 bg_dirty[2];
};

struct drm_vs_rcd_roi {
	__u8 top_enable;
	__u8 btm_enable;
	struct drm_vs_rect top_roi;
	struct drm_vs_rect btm_roi;
};

struct drm_vs_dec_enable {
	__u8 lossy;
	enum drm_vs_dec_pos pos;
};

struct drm_vs_wb_frm_done {
	__u8 wb_id;
	__u8 wb_frm_done;
};

struct drm_vs_reset {
	enum drm_vs_reset_mode mode;
};

struct drm_vs_sw_reset {
	enum drm_vs_sw_reset_mode reset_mode;
};

struct drm_vs_hist {
	enum drm_vs_hist_idx idx;
	__u8 hist_enable;
	enum drm_vs_hist_pos pos;
	enum drm_vs_hist_bin_mode bin_mode;
	__u32 coef[3];
};

struct drm_vs_hist_roi {
	enum drm_vs_hist_idx idx;
	struct drm_vs_rect rect;
};

struct drm_vs_hist_block {
	enum drm_vs_hist_idx idx;
	struct drm_vs_rect rect;
};

struct drm_vs_hist_prot {
	enum drm_vs_hist_idx idx;
	__u8 prot_enable;
};

struct drm_vs_hist_info {
	enum drm_vs_hist_idx idx;
	enum drm_vs_hist_out_mode out_mode;
	struct drm_vs_data_block *buffer;
	__u32 fd;
	__u32 hist_bo_handle;
};

struct drm_vs_hist_get {
	enum drm_vs_hist_idx idx;
	__u32 result[VS_HIST_RESULT_BIN_CNT];
};

struct drm_vs_rgb_hist_get {
	__u32 result[VS_HIST_RESULT_BIN_CNT * 3];
};

struct drm_vs_get_hist_info {
	__u8 crtc_id;
	enum drm_vs_hist_idx idx;
	union _hist_get_u {
		struct drm_vs_hist_get hist;
		struct drm_vs_rgb_hist_get rgb_hist;
	} u;
};

struct drm_vs_pvric_offset {
	__u32 format;
	__u32 handles[3];
	__u32 header_size[3];

	__u64 offsets[3];
};

struct drm_vs_pvric_clear {
	__u64 color[3];
};

struct drm_vs_pvric_const {
	struct drm_vs_color color[2];
};

struct drm_vs_brightness {
	enum drm_vs_brightness_cal_mode mode;
	__u16 target;
	__u16 threshold;
	__u16 luma_coef[3];
};

struct drm_vs_brightness_roi {
	__u8 roi0_enable;
	__u8 roi1_enable;
	struct drm_vs_rect roi0;
	struct drm_vs_rect roi1;
};

struct drm_vs_decompress {
	__u8 lossy;
	__u64 physical;
	__u32 format;
	__u32 tile_type;
	__u64 clear_color;
};

struct drm_vs_gem_query_info {
	enum drm_vs_gem_query_type type;
	__u32 handle;
	__u64 data;
};

struct drm_vs_query_feature_cap {
	enum drm_vs_feature_cap_type type;
	__u32 cap;
};

struct drm_vs_dsc {
	/* Operating mode of the encoder */
	__u8 slices_per_line;
	__u8 ss_num;
	__u16 slice_height;

	__u16 picture_width;
	__u16 picture_height;

	/* For usage model */
	__u8 split_panel_enable;
	__u8 multiplex_mode_enable;
	int multiplex_out_sel;
	__u8 de_raster_enable;
	__u8 multiplex_eoc_enable;
	__u8 video_mode;
};

struct dsc_hw_config {
	/* Dsc version */
	__u8 dsc_version_major;
	__u8 dsc_version_minor;

	/* Define if native 420 and/or native 422 are supported */
	__u8 native_420_enable;
	__u8 native_422_enable;

	/* Number of hard slice encoder */
	__u8 nb_hs_enc;

	/* Number of soft slice context */
	__u8 nb_ss_enc;

	/* Derasterization buffer */
	__u8 derasterization_buffer_enable;

	/**
	 * Max picture size accross all hard slcies.
	 * max_container_pixels_per_line defines the max PICTURE_WIDTH
	 * max_container_pixels_hs_line defines the max PICTURE_WIDTH within
	 *     a single Hard Slice Encoder when used in independent mode,
	 *     or the max SLICE_WIDTH when used in split mode.
	 * max_lines defines the max PICTURE_HEIGHT.
	 */
	int max_container_pixels_per_line;
	int max_container_pixels_hs_line;
	int max_lines;

	/**
	 * Max number of bits per component.
	 * for R/G/B & YCbCr reconstructed pixels */
	int max_bpc;

	/* Output data interface width */
	int output_data_width;

	/* Output buffer RAMs addr bus width*/
	int ob_addr_width;
};

struct drm_vs_vdc {
	/* Operating mode of the encoder */
	__u8 slices_per_line;
	__u8 ss_num;
	__u16 slice_height;

	/* For usage model */
	__u8 split_panel_enable;
	__u8 multiplex_mode_enable;
	int multiplex_out_sel;
	__u8 multiplex_eoc_enable;
	__u8 hs_split_input_enable;
	__u8 video_mode;
};

struct drm_vs_hdr {
	__u8 demultiply;
	__u8 eotf_enable;
	__u8 gamut_map_enable;
	__u8 tone_map_enable;
	__u8 oetf_enable;

	struct drm_vs_xstep_lut eotf_config;

	struct drm_vs_gamut_map gamut_map;

	struct drm_vs_tone_map tone_map;

	struct drm_vs_xstep_lut oetf_config;
};

struct drm_vs_nr_config {
	__u32 coef[VS_NR_COEF_NUM];
};

struct drm_vs_ssr3_config {
	/* for RTL */
	__u32 DepHWid;
	__u32 DepVWid;
	int HWidRatio;
	int VWidRatio;
	int HRatioSft;
	int VRatioSft;
	/* ssr3 param */
	__u32 coef[VS_SSR3_COEF_NUM];
};

struct drm_vs_sr2000 {
	__u8 r2y_enable;
	__u8 scale_enable;
	__u8 nr_enable;
	__u8 ssr3_enable;
	__u8 y2r_enable;
	struct drm_vs_r2y_config r2y;
	struct drm_vs_scale_config scale;
	struct drm_vs_nr_config nr;
	struct drm_vs_ssr3_config ssr3;
	struct drm_vs_y2r_config y2r;
};

struct dc_dec400_fc {
	__u8 fc_enable;
	__u32 fc_size;
	__u32 fc_rgby_value;
	__u32 fc_uv_value;
};

struct drm_vs_ctx {
	__u32 handle;
	__u32 type;
	__u32 frm_rdy_count;
	__u32 frm_exe_count;
	__u8 is_update_ltm;
	__u32 hist_frm_id;
	__u32 update_frm_id;
	__u32 slope[VS_LTM_AFFINE_LUT_NUM];
	__u32 bias[VS_LTM_AFFINE_LUT_NUM];
};

struct drm_vs_ctx_id {
	__u32 id;
};

struct drm_vs_vcmd_exception {
	__u32 ctx_id;
	__u32 error_code;
	__u32 err_ctx;
	__u32 err_frm;
	__u32 rerun_ctx;
	__u32 rerun_frm;
	__u32 skipped_ctx0;
	__u32 skipped_frm0;
	__u32 skipped_ctx1;
	__u32 skipped_frm1;
	__u8 skipped_two_frms;
	__u8 sign_up;
};

struct drm_vs_dc_exception {
	__u32 error_code;
	__u8 sign_up;
};

#define DRM_VS_GET_FBC_OFFSET 0x00
#define DRM_VS_SW_RESET 0x01
#define DRM_VS_GEM_QUERY 0x04
#define DRM_VS_GET_FEATURE_CAP 0x05
#define DRM_VS_GET_HIST_INFO 0x06
#define DRM_VS_GET_WB_FRM_DONE 0x07
#define DRM_VS_SET_CTX 0x08
#define DRM_VS_CLEAN_SW_RESET 0x09
#define DRM_VS_GET_VCMD_EXCEPTION 0x0A
#define DRM_VS_GET_DC_EXCEPTION 0x0B

#define DRM_IOCTL_VS_GET_FBC_OFFSET \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_VS_GET_FBC_OFFSET, struct drm_vs_pvric_offset)
#define DRM_IOCTL_VS_SW_RESET DRM_IOWR(DRM_COMMAND_BASE + DRM_VS_SW_RESET, struct drm_vs_reset)
#define DRM_IOCTL_VS_GEM_QUERY \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_VS_GEM_QUERY, struct drm_vs_gem_query_info)
#define DRM_IOCTL_VS_GET_FEATURE_CAP \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_VS_GET_FEATURE_CAP, struct drm_vs_query_feature_cap)
#define DRM_IOCTL_VS_GET_HIST_INFO \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_VS_GET_HIST_INFO, struct drm_vs_get_hist_info)
#define DRM_IOCTL_VS_GET_WB_FRM_DONE \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_VS_GET_WB_FRM_DONE, struct drm_vs_wb_frm_done)
/*DC9000SR: muti-context*/
#define DRM_IOCTL_VS_SET_CTX DRM_IOWR(DRM_COMMAND_BASE + DRM_VS_SET_CTX, struct drm_vs_ctx)
#define DRM_IOCTL_VS_CLEAN_SW_RESET \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_VS_CLEAN_SW_RESET, struct drm_vs_sw_reset)
#define DRM_IOCTL_VS_GET_VCMD_EXCEPTION \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_VS_GET_VCMD_EXCEPTION, struct drm_vs_vcmd_exception)
#define DRM_IOCTL_VS_GET_DC_EXCEPTION \
	DRM_IOWR(DRM_COMMAND_BASE + DRM_VS_GET_DC_EXCEPTION, struct drm_vs_dc_exception)

#endif /* __VS_DRM_H__ */
