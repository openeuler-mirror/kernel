/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 VeriSilicon Holdings Co., Ltd.
 */

#ifndef __VS_EGT_DRM_H__
#define __VS_EGT_DRM_H__

#include <drm/drm.h>
#include <linux/types.h>

#define VS_EGT_MAX_COLOR_BAR_NUM 16
#define VS_EGT_MAX_LUT_SEG_CNT 10
#define VS_EGT_MAX_GAMMA_ENTRY_CNT 257

#define VS_EGT_LTM_CD_RESULT_NUM 256
#define VS_EGT_LTM_HIST_RESULT_NUM 9216 /* 12x12x64 */
#define VS_EGT_HIST_RESULT_BIN_CNT 256

#define VS_EGT_MAX_Y2R_COEF_NUM 15
#define VS_EGT_MAX_R2Y_COEF_NUM 15
#define VS_EGT_MAX_ROI_CNT 2

struct drm_vs_egt_rect {
	__u16 x;
	__u16 y;
	__u16 w;
	__u16 h;
};

struct drm_vs_egt_color {
	__u32 a;
	__u32 r;
	__u32 g;
	__u32 b;
};

enum drm_vs_egt_data_extend_mode {
	VS_EGT_DATA_EXT_STD = 0,
	VS_EGT_DATA_EXT_MSB = 1,
	VS_EGT_DATA_EXT_RANDOM = 2,
};

enum drm_vs_egt_gem_query_type {
	VS_EGT_GEM_QUERY_HANDLE = 0,
};

struct drm_vs_egt_gem_query_info {
	enum drm_vs_egt_gem_query_type type;
	__u32 handle;
	__u64 data;
};

enum drm_vs_egt_sync_dc_mode {
	VS_EGT_SINGLE_DC = 0,
	VS_EGT_MULTI_DC_PRIMARY = 1,
	VS_EGT_MULTI_DC_SECONDARY = 2,
};

struct drm_vs_egt_gamma_lut {
	__u32 seg_cnt;
	__u32 seg_point[VS_EGT_MAX_LUT_SEG_CNT - 1];
	__u32 seg_step[VS_EGT_MAX_LUT_SEG_CNT];
	__u32 entry_cnt;
	struct drm_vs_egt_color data[VS_EGT_MAX_GAMMA_ENTRY_CNT];
	/*SR: use gamma soft-alog, need refine*/
	struct drm_vs_egt_color seg_cnt_sr;
	struct drm_vs_egt_color seg_point_sr[VS_EGT_MAX_LUT_SEG_CNT - 1];
	struct drm_vs_egt_color seg_step_sr[VS_EGT_MAX_LUT_SEG_CNT];
	struct drm_vs_egt_color entry_cnt_sr;
};

struct drm_vs_egt_ltm_luma_ave {
	__u8 enable;
	__u16 margin_x;
	__u16 margin_y;
	__u16 pixel_norm;
	__u16 ave;
};

struct drm_vs_egt_ltm_cd_get {
	__u32 result[VS_EGT_LTM_CD_RESULT_NUM];
};

struct drm_vs_egt_ltm_hist_get {
	__u8 enable;
	__u32 fd;
	__u32 hist_bo_handle;
	__u32 result[VS_EGT_LTM_HIST_RESULT_NUM];
};

enum drm_vs_egt_hist_idx {
	VS_EGT_HIST_IDX_0,
	VS_EGT_HIST_IDX_1,
	VS_EGT_HIST_IDX_2,
	VS_EGT_HIST_IDX_3,
	VS_EGT_HIST_IDX_RGB,
	VS_EGT_HIST_IDX_COUNT,
};

struct drm_vs_egt_hist_get {
	enum drm_vs_egt_hist_idx idx;
	__u32 result[VS_EGT_HIST_RESULT_BIN_CNT];
};

struct drm_vs_egt_rgb_hist_get {
	__u32 result[VS_EGT_HIST_RESULT_BIN_CNT * 3];
};

struct drm_vs_egt_pvric_offset {
	__u32 format;
	__u32 handles[3];
	__u32 header_size[3];

	__u64 offsets[3];
};

enum drm_vs_egt_reset_mode {
	VS_EGT_RESET = 0,
	VS_EGT_FE0_RESET = 1,
	VS_EGT_FE1_RESET = 2,
	VS_EGT_BE_RESET = 3,
};

struct drm_vs_egt_reset {
	enum drm_vs_egt_reset_mode mode;
};

enum drm_vs_egt_feature_cap_type {
	VS_EGT_FEATURE_CAP_FBC = 0,
	VS_EGT_FEATURE_CAP_MAX_BLEND_LAYER,
	VS_EGT_FEATURE_CAP_CURSOR_WIDTH,
	VS_EGT_FEATURE_CAP_CURSOR_HEIGHT,
	VS_EGT_FEATURE_CAP_LINEAR_YUV_ROTATION,
	VS_EGT_FEATURE_CAP_ANY_RESOLUTION,
	VS_EGT_FEATURE_CAP_MAX_WIDTH,
	VS_EGT_FEATURE_CAP_MAX_HEIGHT,
	VS_EGT_FEATURE_CAP_USE_VCMD,
	VS_EGT_FEATURE_CAP_VCMD_CMDBUF_REMAINING,
};

struct drm_vs_egt_query_feature_cap {
	enum drm_vs_egt_feature_cap_type type;
	__u32 cap;
};

struct drm_vs_egt_get_hist_info {
	__u8 crtc_id;
	enum drm_vs_egt_hist_idx idx;
	union _hist_get_u {
		struct drm_vs_egt_hist_get hist;
		struct drm_vs_egt_rgb_hist_get rgb_hist;
	} u;
};

struct drm_vs_egt_watermark {
	__u32 watermark;
	__u8 qos_low;
	__u8 qos_high;
};

enum drm_vs_egt_csc_mode {
	VS_EGT_CSC_CM_USR,
	VS_EGT_CSC_CM_L2L,
	VS_EGT_CSC_CM_L2F,
	VS_EGT_CSC_CM_F2L,
	VS_EGT_CSC_CM_F2F,
};

enum drm_vs_egt_csc_gamut {
	VS_EGT_CSC_CG_601,
	VS_EGT_CSC_CG_709,
	VS_EGT_CSC_CG_2020,
	VS_EGT_CSC_CG_P3,
	VS_EGT_CSC_CG_SRGB,
};

struct drm_vs_egt_y2r_config {
	enum drm_vs_egt_csc_mode mode;
	enum drm_vs_egt_csc_gamut gamut;
	__s32 coef[VS_EGT_MAX_Y2R_COEF_NUM];
};

/*need to refine*/
struct drm_vs_egt_data_block {
	__u32 size; /* total size of data block buffer */
	__u64 logical;
};

struct drm_vs_egt_pvric_clear {
	__u64 color[3];
};

struct drm_vs_egt_pvric_const {
	struct drm_vs_egt_color color[2];
};

enum drm_vs_egt_plane_crc_pos {
	VS_EGT_PLANE_CRC_DFC = 0,
	VS_EGT_PLANE_CRC_HDR = 1,
};

enum drm_vs_egt_disp_crc_pos {
	VS_EGT_DISP_CRC_BLD = 0,
	VS_EGT_DISP_POST_PROC = 1,
	VS_EGT_DISP_CRC_OFIFO_IN = 2,
	VS_EGT_DISP_CRC_OFIFO_OUT = 3,
	VS_EGT_DISP_CRC_WB = 4,
};

struct drm_vs_egt_r2y_config {
	enum drm_vs_egt_csc_mode mode;
	enum drm_vs_egt_csc_gamut gamut;
	__s32 coef[VS_EGT_MAX_R2Y_COEF_NUM];
	/* For debug, the output bus format.
	 *     Usually the output bus format info from encoder.
	 *     In our driver, the default output bus format is MEDIA_BUS_FMT_RGB888_1X24
	 *     For the convernience of debugging, adding an output bus format setting
	 *     here for debugging the writeback data.
	 */
	__u32 output_bus_format;
};

enum drm_vs_egt_blend_mode {
	VS_EGT_BLD_CLR = 0,
	VS_EGT_BLD_SRC = 1,
	VS_EGT_BLD_DST = 2,
	VS_EGT_BLD_SRC_OVR = 3,
	VS_EGT_BLD_DST_OVR = 4,
	VS_EGT_BLD_SRC_IN = 5,
	VS_EGT_BLD_DST_IN = 6,
	VS_EGT_BLD_SRC_OUT = 7,
	VS_EGT_BLD_DST_OUT = 8,
	VS_EGT_BLD_SRC_ATOP = 9,
	VS_EGT_BLD_DST_ATOP = 10,
	VS_EGT_BLD_XOR = 11,
	VS_EGT_BLD_PLUS = 12,
	VS_EGT_BLD_BLD = 13,
	VS_EGT_BLD_UDEF = 14,
};

struct drm_vs_egt_blend {
	enum drm_vs_egt_blend_mode color_mode;
	enum drm_vs_egt_blend_mode alpha_mode;
};

enum drm_vs_egt_alpha_mode {
	VS_EGT_ALPHA_NORMAL = 0,
	VS_EGT_ALPHA_INVERSE = 1,
};

enum drm_vs_egt_galpha_mode {
	VS_EGT_GALPHA_NORMAL = 0,
	VS_EGT_GALPHA_GLOBAL = 1,
	VS_EGT_GALPHA_MULTIPLE = 2,
};

struct drm_vs_egt_blend_alpha {
	/* src alpha pre process */
	enum drm_vs_egt_alpha_mode sam;
	enum drm_vs_egt_galpha_mode sgam;
	__u32 sga;
	__u32 saa;

	/* dst alpha pre process */
	enum drm_vs_egt_alpha_mode dam;
	enum drm_vs_egt_galpha_mode dgam;
	__u32 dga;
	__u32 daa;
};

struct drm_vs_egt_colorkey {
	__u32 colorkey;
	__u32 colorkey_high;
	__u8 transparency;
};

enum drm_vs_egt_dma_mode {
	/* read full image */
	VS_EGT_DMA_NORMAL = 0,
	/* read one ROI region in the image */
	VS_EGT_DMA_ONE_ROI = 1,
	/* read two ROI regions in the image */
	VS_EGT_DMA_TWO_ROI = 2,
	/* skip the ROI region in the image */
	VS_EGT_DMA_SKIP_ROI = 3,
	/* for extend layer mode
	 * read full image0 and image1, don't.
	 */
	VS_EGT_DMA_EXT_LAYER = 4,
	/* for extend layer mode
	 * read ROI region from image0 and
	 * read exrended ROI region from image1.
	 */
	VS_EGT_DMA_EXT_LAYER_EX = 5,
};

struct drm_vs_egt_dma {
	enum drm_vs_egt_dma_mode mode;
	/* in_rect[0] is available under the DMA mode:
	 *	   VS_EGT_DMA_ONE_ROI: the ROI region rectangle.
	 *	   VS_EGT_DMA_TWO_ROI: the first ROI region rectangle.
	 *	   VS_EGT_DMA_SKIP_ROI: the skip ROI region rectangle.
	 *	   VS_EGT_DMA_EXT_LAYER_EX: the ROI region rectangle of first image.
	 * in_rect[1] is avilable under the DMA mode:
	 *	   VS_EGT_DMA_TWO_ROI: the seconf ROI region rectangle.
	 *	   VS_EGT_DMA_EXT_LAYER_EX: the ROI region rectangle of second image.
	 */
	struct drm_vs_egt_rect in_rect[VS_EGT_MAX_ROI_CNT];
	/* out_rect[0] is available under the DMA mode:
	 *	   VS_EGT_DMA_ONE_ROI: specify the ROI out region.
	 *	   VS_EGT_DMA_TWO_ROI: specify the first ROI out region.
	 *	   VS_EGT_DMA_SKIP_ROI: specify skip ROI out region.
	 *	   VS_EGT_DMA_EXT_LAYER: specify the first image out region.
	 *	   VS_EGT_DMA_EXT_LAYER_EX: specify the ROI out region of first image.
	 * out_rect[1] is avilable under the DMA mode:
	 *	   VS_EGT_DMA_TWO_ROI: specify the seconf ROI out region.
	 *	   VS_EGT_DMA_EXT_LAYER: specify the second image out region.
	 *	   VS_EGT_DMA_EXT_LAYER_EX: specify the ROI out region of second image.
	 */
	struct drm_vs_egt_rect out_rect[VS_EGT_MAX_ROI_CNT];
};

enum drm_vs_egt_dth_frm_idx {
	VS_EGT_DTH_FRM_IDX_NONE = 0,
	VS_EGT_DTH_FRM_IDX_SW = 1,
	VS_EGT_DTH_FRM_IDX_HW = 2,
};

enum drm_vs_egt_dth_frm_mode {
	VS_EGT_DTH_FRM_4 = 4,
	VS_EGT_DTH_FRM_8 = 8,
	VS_EGT_DTH_FRM_16 = 16,
};

struct drm_vs_egt_dither {
	enum drm_vs_egt_dth_frm_idx index_type;
	__u8 sw_index;
	__u32 table_low[3];
	__u32 table_high[3];
	enum drm_vs_egt_dth_frm_mode frm_mode;
};

enum drm_vs_egt_wb_point {
	VS_EGT_WB_DISP_OUT = 0,
	VS_EGT_WB_DISP_IN = 1,
	VS_EGT_WB_DISP_CC = 2,
	VS_EGT_WB_OFIFO_IN = 3,
	VS_EGT_WB_OFIFO_OUT = 4,
	VS_EGT_WB_POS_CNT = 5,
};

enum drm_vs_egt_mmu_prefetch_mode {
	VS_EGT_MMU_PREFETCH_DISABLE = 0,
	VS_EGT_MMU_PREFETCH_ENABLE = 1,
};

#endif /* __VS_EGT_DRM_H__ */

