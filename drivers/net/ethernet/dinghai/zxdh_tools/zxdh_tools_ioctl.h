/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef ZXDH_TOOLS_IOCTL_H_
#define ZXDH_TOOLS_IOCTL_H_

#include <linux/dinghai/log.h>
#include "../en_aux.h"
#include "../en_np/table/include/dpp_tbl_pkt_cap.h"
#include "../en_aux/en_aux_cmd.h"
//#define       ZXDH_TOOLS_MSGQ

#define SAFE_KFREE(ptr)               \
	do {                          \
		if ((ptr) != NULL) {  \
			kfree(ptr);   \
			(ptr) = NULL; \
		}                     \
	} while (0)

#define DHTOOL_COMPAT_ITM (0)
#define DHTOOL_COMPAT_MAJOR (0)
#define DHTOOL_COMPAT_DRIV_MINOR (0)
#define DHTOOL_COMPAT_TOOL_MINOR (0)
#define DHTOOL_COMPAT_PATCH (0)

#define DH_SWITCH_DEVICE_ID 0x8036
#define DH_SWITCH_VENDOR_ID 0x1cf2

#define MAX_DHTOOL_PID_NUMS 15
#define DHTOOL_ERROR 0x1a
#define max_entry_num 68
#define key_entry_num 2
#define normal_tcam_index 60
#define key_tcam_index 68
#define ZXDH_PKT_FLAG 0xbb
#define PKT_PAYLIAD_VALUE 255
#define ZXDH_PKT_INIT_SPEED 10000
#define ZXDH_PKT_HEDER_LENGTH 20
#define EIGHT_HOURS_SECONDS (8 * 3600)

#define DBDF_ECAM(domain, bus, devid, func) \
	(((domain & 0xffff) << 16) | ((bus & 0xff) << 8) | ((devid & 0x1f) << 3) | (func & 0x07))

enum MSG_SUBCMD {
	MSG_MARK_INFO = 0,
	MSG_SEND_TO_RISCV,
	MSG_DEVICE_INFO_GET,
	MSG_SET_VF_STATUS,
	MSG_DEVICE_PHYPORT_GET,
	MSG_PKT_CAPTURE = 5,
	MSG_GET_DRV_VERSION = 6,
	MSG_SET_VF_MAC = 7,
	MSG_GET_SW_STAT = 8,
	SUBCMD_NUM = 10,
};

struct zxdh_pkt_capture_msg {
	u32 op_code;
	u16 payload_len;
	u8 payload[];
} __packed;

enum dhtool_pkt_capture_main_cmd_index {
	DHTOOL_PKT_CAPTURE_CMD_ENABLE = 0,
	DHTOOL_PKT_CAPTURE_CMD_DISABLE,
	DHTOOL_PKT_CAPTURE_CMD_DISABLE_ALL,
	DHTOOL_PKT_CAPTURE_CMD_RULE_INSERT,
	DHTOOL_PKT_CAPTURE_CMD_RULE_DELETE,
	DHTOOL_PKT_CAPTURE_CMD_SHOW,
	DHTOOL_PKT_CAPTURE_CMD_SAVE_TO_FILE,
	DHTOOL_PKT_CAPTURE_CMD_SET_SPEED,
	DHTOOL_PKT_CAPTURE_CMD_ERROR
};

enum DHTOOL_RESPONSE {
	MSG_RECV_OK = 1,
	MSG_RECV_FAILED = 2,
	MSG_RECV_PKT_CAP_PF_LOCK = 3,
	MSG_RECV_PKT_FILE_PATH_ERR = 4,
	MSG_RECV_PKT_FILE_EXIST_ERR = 5,
	MSG_RECV_PKT_FILE_IN_PROGRESS_ERR = 6,
};

enum SWITCH_FLAG {
	NO_SWITCH = 0,
	SWITCH = 1,
};

struct zxdh_tools_msg {
	u32 subcmd; //provider care
	u32 event_pid; //provider care
	void *tools_reps; //provider care
	u32 event_id; //caller care
	u16 dst; //caller care
	u16 dst_pcieid; //caller care
	void *msg_reps; //caller care
	u16 msg_reps_len; //caller care
	u16 sync_or_async; //caller care
	u16 payload_len; //caller care
	u16 reserved; //caller care
	u8 payload[];
} __packed;

struct zxdh_tools_reps {
	u32 status; /* must be */
	s32 bar_or_vq_chan_ret;
	u32 data[15];
};

struct zxdh_tools_ioctl_subcmd_info {
	enum MSG_SUBCMD subcmd;
	s32 (*subcmd_callback)(struct net_device *netdev, struct ifreq *ifr);
};

struct dhtool_dev_pcieid_get {
	u32 dev_pcieid;
};
struct dhtool_dev_info {
	u32 domain_no;
	u32 bus_no;
	u32 device_no;
	u32 func_no;
};

struct dhtool_dev_info_get_reps {
	enum SWITCH_FLAG switch_or_noswitch;
	struct dhtool_dev_info dev_info;
	struct dhtool_dev_info rp_info;
	union {
		struct dhtool_dev_info swusp_info;
	};
};

struct dhtool_eventpid_devbdf_array {
	bool is_valid;
	u16 dev_pcieid;
	u32 dev_bdf;
	u32 event_pid;
};

enum VF_SET_MODE { ALL_VF, VF3_MAX };

enum VF_SET_STATUS { VF_STATUS_AUTO, VF_STATUS_ENABLE, VF_STATUS_DISABLE };

struct dhtool_set_vf_status_msg {
	enum VF_SET_MODE mode;
	enum VF_SET_STATUS vf_status;
};

struct dhtool_dev_phyport_get {
	u8 phyport;
	u8 rsv[15];
};

struct pkt_deve_name {
	char dev_name[IFNAMSIZ];
};

struct zxdh_pkt_cap_cmd_save_to_file {
	char file_path[150];
	u32 file_size;
	u32 pkt_count;
	u32 is_stop;
};

struct zxdh_pkt_cap_rule_rule_insert {
	u32 rule_index;
	enum zxdh_pkt_cap_point cap_point;
	enum zxdh_pkt_cap_mode cap_mode;
	struct zxdh_pkt_cap_key pkt_cap_key;
	struct zxdh_pkt_cap_normal_configure rule_config;
	char dev_name[IFNAMSIZ];
};

struct zxdh_pkt_cap_rule_rule_delete {
	u32 rule_index;
	u32 is_mode_all;
	u32 is_all;
	enum zxdh_pkt_cap_point cap_point;
	enum zxdh_pkt_cap_mode cap_mode;
};

struct zxdh_pkt_cap_cmd_show {
	u32 speed;
	u32 entry_num;
	u32 file_size;
	u32 pkt_count;
	u32 is_save_to_file;
	struct zxdh_pkt_cap_enable_status enable_status;
	struct zxdh_pkt_cap_rule_rule_insert entry_array[68];
	char file_path[150];
};

typedef u32 (*callback_t)(struct net_device *netdev, struct zxdh_tools_msg *tool_msg,
			  struct zxdh_pkt_capture_msg *pkt_msg, struct dpp_pf_info_t *pf_info);

struct zxdh_pkt_capture_callback_entry_t {
	u32 op_code;
	callback_t callback;
};

struct dhtool_compat_reg {
	u8 version_compat_item;
	u8 major;
	u8 tool_minor;
	u8 drv_minor;
	u16 patch;
	u8 rsv[2];
} __packed;

enum zxdh_cap_status { zxdh_cap_disable, zxdh_cap_enable };

s32 zxdh_tools_ioctl_dispatcher(struct net_device *netdev, struct ifreq *ifr);
ssize_t pkt_packet_to_file(struct zxdh_en_device *en_dev, const char *data, size_t len);
u8 pkt_packet_process(struct zxdh_en_device *en_dev, void *buf, u32 len, u8 pkt_flag);
u8 pkt_skb_packet_process(struct zxdh_en_device *en_dev, struct sk_buff *skb, u8 pkt_flag);
void capture_save_file_work_handler(struct work_struct *work);
void close_log_file(struct file *filp);
#define DHTOOLS_LOG_ERR(fmt, arg...) DH_LOG_ERR(MODULE_DHTOOLS, fmt, ##arg)
#define DHTOOLS_LOG_INFO(fmt, arg...) DH_LOG_INFO(MODULE_DHTOOLS, fmt, ##arg)

#endif
