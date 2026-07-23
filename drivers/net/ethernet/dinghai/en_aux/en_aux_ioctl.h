/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _EN_AUX_IOCTL_H_
#define _EN_AUX_IOCTL_H_
#include "../en_aux.h"

#define SIOCDEVPRIVATE_WRITE_MAC (SIOCDEVPRIVATE + 1)
#define SIOCDEVPRIVATE_VQ_INFO (SIOCDEVPRIVATE + 2)
#define SIOCDEVPRIVATE_MSGQ_SNED (SIOCDEVPRIVATE + 3)
#define SIOCDEVPRIVATE_MSGQ_CONFIG (SIOCDEVPRIVATE + 4)
#define SIOCDEVPRIVATE_SEND_FILE_PKT (SIOCDEVPRIVATE + 6)
#define SIOCDEVPRIVATE_PTP_FUNC (SIOCDEVPRIVATE + 9)
#define SIOCDEVPRIVATE_PPS_FUNC (SIOCDEVPRIVATE + 10)
#define SIOCDEVPRIVATE_TSN_FUNC (SIOCDEVPRIVATE + 11)
#define SIOCDEVPRIVATE_DH_TOOLS (SIOCDEVPRIVATE + 13)

#define PTP_SET_CLOCK_NO (0)
#define PTP_ENABLE_PTP_ENCRYPTED_MSG (1)
#define PTP_SET_INTR_CAPTURE_TIMER (2)
#define PTP_SET_PP1S_SELECTION (3)
#define PTP_SET_PHASE_DETECTION (4)
#define PTP_GET_PD_VALUE (5)
#define PTP_SET_L2PTP_PORT (6)
#define PTP_SET_PTP_EC_ENABLE (7)
#define PTP_SET_SYNCE_CLK_PORT (8)
#define PTP_GET_SYNCE_CLK_STATS (9)
#define PTP_SET_SPM_PORT_TSTAMP_ENABLE (10)
#define PTP_GET_SPM_PORT_TSTAMP_ENABLE (11)
#define PTP_SET_SPM_PORT_TSTAMP_MODE (12)
#define PTP_GET_SPM_PORT_TSTAMP_MODE (13)
#define PTP_SET_DELAY_STATISTICS_ENABLE (14)
#define PTP_GET_DELAY_STATISTICS_VALUE (15)
#define PTP_CLR_DELAY_STATISTICS_VALUE (16)
#define PTP_SET_LOCAL_PPS_INTERRUPT_ENABLE (17)
#define PTP_SET_EXT_PPS_INTERRUPT_ENABLE (18)
#define PTP_SET_PD_SEL_SHIFT (19)
#define PTP_GET_PTP_CLOCK_INDEX (20)

#define PI_HDR_MAX_NUM 128
#define GET_LOW32 0x00000000ffffffff
#define MIN_ALIGN_BYTE 64
#define SEND_PKT_CNT_MAX 0xffffffff
#define PKT_PRINT_LINE_LEN 16
#define PKT_PRINT_LEN_MAX (16 * 1024)

#define CONFIG_RISC_PCS_LOOPB_OPCODE 13
#define CONFIG_RISC_PCS_NORMAL_OPCODE 14

#define MSG_MODULE_DEBUG_RISC 20

#define MAX_ACCESS_NUM 500
struct zxdh_en_reg {
	u32 offset;
	u32 num;
	u32 data[MAX_ACCESS_NUM];
};

struct risc_config_mac_msg {
	u8 op_code;
	u8 phyport;
	u8 spm_speed;
	u8 spm_fec;
	u8 loop_enable;
};

struct risc_config_userspace {
	u8 op_code;
	u8 arg_num;
	u8 filestr_size;
	u8 file[100];
};

struct data_packet {
	void *buf;
	u32 buf_size;
};

struct zxdh_en_ioctl_table {
	s32 cmd;
	s32 (*func)(struct net_device *netdev, struct ifreq *ifr);
};

struct zxdh_en_ptp_ioctl_table {
	s32 cmd;
	s32 (*func)(struct net_device *netdev, struct ifreq *ifr, struct zxdh_en_reg *reg);
};

s32 print_data(u8 *data, u32 len);
s32 zxdh_en_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd);

s32 zxdh_en_private_ioctl(struct net_device *netdev, struct ifreq *ifr, void *data, int cmd);

#ifdef PTP_DRIVER_INTERFACE_EN
s32 enable_write_ts_to_fifo(struct zxdh_en_device *en_dev, u32 enable, u32 mac_number);
s32 set_interrupt_capture_timer(struct zxdh_en_device *en_dev, u32 index);
s32 zxdh_set_pps_selection(struct zxdh_en_device *en_dev, u32 pps_type, u32 selection);
s32 zxdh_set_pd_detection(struct zxdh_en_device *en_dev, u32 pd_index, u32 pd_input1,
			  u32 pd_input2);
s32 zxdh_get_pd_value(struct zxdh_en_device *en_dev, u32 pd_index, u32 *pd_result);
s32 zxdh_set_pps_interrupt_support(struct zxdh_en_device *en_dev, u32 support);
s32 zxdh_get_pps_interrupt_support(struct zxdh_en_device *en_dev, u32 *support);
s32 zxdh_set_local_pps_interrupt_enable(struct zxdh_en_device *en_dev, u32 enable);
s32 zxdh_set_ext_pps_interrupt_enable(struct zxdh_en_device *en_dev, u32 pps_src, u32 enable);
s32 zxdh_set_pd_sel_shift(struct zxdh_en_device *en_dev, u32 pd_index, u32 sel, u32 shift);
s32 zxdh_get_ptp_clock_index(struct zxdh_en_device *en_dev, u32 *ptp_clock_idx);
#endif /* PTP_DRIVER_INTERFACE_EN */

#endif
