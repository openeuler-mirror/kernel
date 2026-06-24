/* SPDX-License-Identifier: GPL-2.0 */
/*
 * DisplayPort Driver Header
 *
 * Copyright (c) 2019-2026, New H3C Semiconductor Technologies Co., Ltd.
 */

#ifndef __EGT_DP_H__
#define __EGT_DP_H__

#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/phy/phy.h>
#include <drm/drm_crtc_helper.h>
#include <drm/display/drm_dp_helper.h>
#include <drm/drm_panel.h>
#include <drm/drm_encoder.h>

/* mbox */
#define EGT_SIOMBOX_CTRL					0x14
#define EGT_DC_TIMING_UPDATE				1
#define EGT_DC_TIMING_STOP					2
#define EGT_DC_RESET_DONE					3
#define EGT_DP_SIO_IOBASE					(0xa00)
#define EGT_DP_SIO_IO_CH1					(EGT_DP_SIO_IOBASE + 0x30)

/* version and cap */
#define EGT_DP_MIN_WIDTH					800
#define EGT_DP_MIN_HEIGHT					600
#define EGT_DP_MAX_WIDTH					1920
#define EGT_DP_MAX_HEIGHT					1200
#define EGT_TX_V1_2							0x12
#define EGT_TX_V1_4							0x14
#define EGT_TX_TRAINING_TRIES_MAX			5
#define EGT_TX_CR_DONE_TRIES_MAX			10
#define EGT_TX_MAX_LANES					4
#define EGT_TX_CAPAB_FEC					0

/* mask */
#define EGT_TX_LOGIC_MASK					0x4
#define EGT_TX_LANE_CNT_MASK				0x3E0
#define EGT_TX_LINK_RATE_MASK				0x1FE00000
#define EGT_TX_TP_MASK						0xF
#define EGT_TX_LINK_BW_MASK					0x1F
#define EGT_TX_TIME_MASK					GENMASK(23, 0)
#define EGT_TX_AUXDONE_MASK					(1<<31)
#define EGT_TX_AUXREADY_MASK				(1<<30)

#define EGT_TX_TP_0							0x0
#define EGT_TX_TP_1							0x1
#define EGT_TX_TP_2							0x2
#define EGT_TX_TP_3							0x3
#define EGT_TX_TP_4							0x7
#define EGT_TX_TP_IDLE						0x4

#define EGT_TX_100US_TICKS					1
#define EGT_TX_ENHANCED_MASK				(1<<19)
#define EGT_TX_HPD_LEVEL					0x4
#define EGT_TX_CR_TIME						0x1
#define EGT_TX_CE_TIME						0x2
#define EGT_TX_TRAIN_CR						0
#define EGT_TX_TRAIN_CE						1
#define EGT_TX_ADJUST_LINKRATE				2
#define EGT_TX_ADJUST_LANECOUNT				3
#define EGT_TX_TRAIN_FAILURE				4
#define EGT_TX_TRAIN_SUCCESS				5
#define EGT_TX_LINK_BW_1_62					0x6
#define EGT_TX_LINK_BW_2_7					0xa
#define EGT_TX_LINK_BW_5_4					0x14
#define EGT_TX_PM_DISABLE					0
#define EGT_PCI_INTRREG_OFFSET				0x18c

/* AUX */
#define EGT_DP_AUX_RD_BIT					0x1
#define EGT_DP_AUX_STD_TOUT					(800)
#define EGT_DP_AUX_NATIVE_WR				0x80
#define EGT_DP_AUX_NATIVE_RD				0x90
#define EGT_DP_AUX_ACK						0x00
#define EGT_DP_AUX_NACK						0x10
#define EGT_DP_AUX_DEFER					0x20
#define EGT_DP_AUX_WR_I2C					0x00
#define EGT_DP_AUX_RD_I2C					0x10
#define EGT_DP_AUX_UPDATE_I2C				0x20
#define EGT_DP_AUX_MOT_I2C					0x40
#define EGT_DP_AUX_ACK_I2C					0x00
#define EGT_DP_AUX_NACK_I2C					0x40
#define EGT_DP_AUX_DEFER_I2C				0x80
#define EGT_DP_AUX_READ_BIT					0x1
#define EGT_DP_AUX_RETRY_TIMES				16

/* DP-TX reg */
#define DP_SOURCE_TX_CONTROL				(0x0 * 4)
#define DP_SOURCE_TX_STATUS					(0x1 * 4)
#define DP_SOURCE_TX_CAPAB					(0x4 * 4)
#define DP_SOURCE_PRE_VOLT0					(0x10 * 4)
#define DP_SOURCE_RECONFIG					(0x14 * 4)
#define DP_SOURCE_TIMESTAMP					(0x1f * 4)
#define DP_SOURCE_MSA_COLOUR				(0x2e * 4)
#define DP_SOURCE_PWR_MNG					(0x3c * 4)

/* AUX reg */
#define DP_SOURCE_AUX_CONTROL				(0x100 * 4)
#define DP_SOURCE_AUX_COMMAND				(0x101 * 4)
#define DP_SOURCE_AUX_BYTE0					(0x102 * 4)
#define DP_SOURCE_AUX_BYTE1					(0x103 * 4)
#define DP_SOURCE_AUX_BYTE2					(0x104 * 4)
#define DP_SOURCE_AUX_BYTE3					(0x105 * 4)
#define DP_SOURCE_AUX_PAYLOAD				(0x105 * 4)
#define DP_SOURCE_AUX_RESET					(0x117 * 4)

/* For kernel version below 6.2 compatibility */
#ifndef abs_diff
#define abs_diff(a, b) ({                       \
	typeof(a) __a = (a);                    \
	typeof(b) __b = (b);                    \
	(void)(&__a == &__b);                   \
	__a > __b ? (__a - __b) : (__b - __a);  \
})
#endif


struct egt_dp_supported_mode {
	int width;
	int height;
};

enum egt_dp_ret_flags {
	RET_OK = 0,
	RET_ERROR,
	RET_RETRY,
	RET_OUT,
	RET_TIMEOUT,
};

struct egt_dp_msa_mode {
	u32 out_fmt;
	u32 bpc;
	u32 fmt;
};

struct egt_tr_patttern_mode {
	u8 drm_pattern;
	int egt_pattern;
};

struct egt_displayport_link_config {
	int max_rate;
	u8 max_lanes;
	int link_rate;
	u8 lane_count;
	u8 cr_done_cnt;
	u8 cr_done_oldstate;
};

struct egt_displayport_config {
	u8 misc0;
	u8 bpp;
	u8 bpc;
	u8 num_colors;
	u8 fmt;
};

struct egt_displayport_mode {
	u8 bw_code;
	u8 lane_cnt;
	int pclock;
	const char *fmt;
};

struct egt_displayport_base {
	void __iomem *dp_base;
	void __iomem *pci_mbox_base;
	void __iomem *pci_base;
	void __iomem *dp_phy0_base;
	void __iomem *dp_phy1_base;
	void __iomem *pixel_pll_base;
	void __iomem *crg_base;
	unsigned int mbox_iobase;
};

struct egt_displayport_prop {
	struct drm_property *rate_property;
	struct drm_property *lanes_property;
	struct drm_property *bpc_property;
	struct drm_property *sync_property;
};

struct egt_displayport {
	struct device *dev;
	struct drm_connector connector;
	struct drm_encoder encoder;
	struct drm_device *drm;
	struct drm_dp_aux aux;
	struct egt_displayport_base mem_base;
	struct egt_displayport_prop prop;
	int irq;
	bool enabled;
	bool edid_present;
	bool connected;
	u8 max_lanes;
	u32 max_link_rate;
	int aux_256b_capab;
	u8 dpcd[DP_RECEIVER_CAP_SIZE];
	u8 train_set[EGT_TX_MAX_LANES];
	u8 bw_code;
	u8 lane_cnt;
	int pclock;
	const char *fmt;
	u32 connector_sts;
	struct egt_displayport_config tx_cfg;
	struct egt_displayport_link_config train_cfg;
	struct delayed_work hot_plug_detect;
	struct mutex lock;
};


void egt_dp_set_bits_per_pixel(struct egt_displayport *dp, u32 drm_fourcc);
int egt_dp_device_init(struct drm_device *drm_dev);
void egt_dp_device_deinit(struct drm_device *drm_dev);
void egt_dp_source_video_state(struct drm_device *drm_dev, int state);
u32 egt_dp_msg_send_enable(struct egt_displayport *dp, u32 *data);
void egt_dp_msg_send(struct egt_displayport *dp, u32 type);
void egt_dp_send_stop_vdp(struct drm_device *drm_dev);
void egt_dp_write(u32 value, u32 reg, struct egt_displayport *dp);
u32 egt_dp_read(u32 reg, struct egt_displayport *dp);
void egt_dp_ticks_wait_us(unsigned int delay_us, struct egt_displayport *dp);
void egt_dp_set_hpd_irq(struct egt_displayport *dp, bool enable);
void egt_dptx_hpd_work(struct work_struct *work);

int egt_dp_get_modes(struct drm_connector *connector);
struct drm_encoder *egt_dp_best_encoder(struct drm_connector *connector);
int egt_dp_mode_valid(__maybe_unused struct drm_connector *connector,
							struct drm_display_mode *mode);
enum drm_connector_status egt_dp_connected_detect
			(__maybe_unused struct drm_connector *connector, __maybe_unused bool force);
void egt_dp_destroy(struct drm_connector *connector);
int egt_dp_atomic_set_property(struct drm_connector *connector,
					  __maybe_unused struct drm_connector_state *state,
					  struct drm_property *prop, uint64_t val);
int egt_dp_atomic_get_property(struct drm_connector *connector,
					__maybe_unused const struct drm_connector_state *state,
					struct drm_property *prop, uint64_t *val);
void egt_dp_dis_encoder(struct drm_encoder *encoder);
void egt_dp_en_encoder(struct drm_encoder *encoder);
void egt_dp_atomic_mode_set(struct drm_encoder *encoder,
				struct drm_crtc_state *crtc_state,
				__maybe_unused struct drm_connector_state *connector_state);
int egt_dp_atomic_check(struct drm_encoder *encoder,
					struct drm_crtc_state *crtc_state,
					struct drm_connector_state *conn_state);

#endif /* __EGT_DP_H__ */

