/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2022 - 2026 Mucse Corporation. */

#ifndef _RNPGBE_MBX_FW_H
#define _RNPGBE_MBX_FW_H

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/wait.h>

#define VF2PF_MBOX_VEC(mbx, vf) ((mbx)->vf2pf_mbox_vec_base + 4 * (vf))
#define CPU2PF_MBOX_VEC(mbx) ((mbx)->cpu2pf_mbox_vec)

/* == PF <--> VF mailbox ==== */
#define SHARE_MEM_BYTES 64
#define PF_VF_SHM(mbx, vf)                                                     \
	((mbx)->pf_vf_shm_base +                                                 \
	(mbx)->mbx_mem_size * (vf))
#define PF2VF_COUNTER(mbx, vf) (PF_VF_SHM(mbx, vf) + 0)
#define VF2PF_COUNTER(mbx, vf) (PF_VF_SHM(mbx, vf) + 4)
#define PF_VF_SHM_DATA(mbx, vf) (PF_VF_SHM(mbx, vf) + 8)
#define PF2VF_MBOX_CTRL(mbx, vf) ((mbx)->pf2vf_mbox_ctrl_base + 4 * (vf))
#define PF_VF_MBOX_MASK_LO(mbx) ((mbx)->pf_vf_mbox_mask_lo)
#define PF_VF_MBOX_MASK_HI(mbx) ((mbx)->pf_vf_mbox_mask_hi)
/* === CPU <--> PF === */
#define CPU_PF_SHM(mbx) ((mbx)->cpu_pf_shm_base)
#define CPU2PF_COUNTER(mbx) (CPU_PF_SHM(mbx) + 0)
#define PF2CPU_COUNTER(mbx) (CPU_PF_SHM(mbx) + 4)
#define CPU_PF_SHM_DATA(mbx) (CPU_PF_SHM(mbx) + 8)
#define PF2CPU_MBOX_CTRL(mbx) ((mbx)->pf2cpu_mbox_ctrl)
#define CPU_PF_MBOX_MASK(mbx) ((mbx)->cpu_pf_mbox_mask)
#define MBOX_CTRL_REQ BIT(0) /* WO */
#define MBOX_CTRL_PF_HOLD_SHM BIT(3) /* VF:RO, PF:WR */
#define MBOX_IRQ_EN 0
#define MBOX_IRQ_DISABLE 1
#define mbx_prd32(hw, reg) prnpgbe_rd_reg((hw)->hw_addr + (reg))
#define mbx_rd32(hw, reg) rnpgbe_rd_reg((hw)->hw_addr + (reg))
#define mbx_pwr32(hw, reg, val) p_rnpgbe_wr_reg((hw)->hw_addr + (reg), (val))
#define mbx_wr32(hw, reg, val) rnpgbe_wr_reg((hw)->hw_addr + (reg), (val))

struct mbx_fw_cmd_reply;
typedef void (*cookie_cb)(struct mbx_fw_cmd_reply *reply, void *priv);

struct mbx_req_cookie {
	int magic;
#define COOKIE_MAGIC 0xCE
	cookie_cb cb;
	int timeout_jiffes;
	int errcode;
	wait_queue_head_t wait;
	int done;
	int priv_len;
	char priv[64];
};

enum GENERIC_CMD {
	/* generate */
	GET_VERSION = 0x0001,
	/* link configuration admin commands */
	GET_PHY_ABALITY = 0x0601,
	GET_MAC_ADDRES = 0x0602,
	RESET_PHY = 0x0603,
	LED_SET = 0x0604,
	GET_LINK_STATUS = 0x0607,
	LINK_STATUS_EVENT = 0x0608,
	SET_LANE_FUN = 0x0609,
	GET_LANE_STATUS = 0x0610,
	SFP_SPEED_CHANGED_EVENT = 0x0611,
	SET_EVENT_MASK = 0x0613,
	SET_LOOPBACK_MODE = 0x0618,
	SET_PHY_REG = 0x0628,
	GET_PHY_REG = 0x0629,
	PHY_LINK_SET = 0x0630,
	GET_PHY_STATISTICS = 0x0631,
	PHY_PAUSE_SET = 0x0632,
	PHY_PAUSE_GET = 0x0633,
	PHY_EEE_SET = 0x0636,
	PHY_EEE_GET = 0x0637,
	/* fw update */
	FW_UPDATE = 0x0700,
	FW_MAINTAIN = 0x0701,
	FW_UPDATE_GBE = 0x0702,
	/* virtualization */
	IFUP_DOWN = 0x0800,
	SEND_TO_PF = 0x0801,
	SEND_TO_VF = 0x0802,
	DRIVER_INSMOD = 0x0803,
	SYSTEM_SUSPUSE = 0x0804,
	SYSTEM_FORCE = 0x0805,
	/*sfp-module*/
	SFP_MODULE_READ = 0x0900,
	SFP_MODULE_WRITE = 0x0901,
	WOL_EN = 0x0910,
	GET_DUMP = 0x0a00,
	SET_DUMP = 0x0a10,
	GET_TEMP = 0x0a11,
	SET_WOL = 0x0a12,
	SET_TEST_MODE = 0x0a13,
	SHOW_TX_STAMP = 0x0a14,
	LLDP_TX_CTRL = 0x0a15,
	READ_REG = 0xFF03,
	WRITE_REG = 0xFF04,
	MODIFY_REG = 0xFF07,
};

enum link_event_mask {
	EVT_LINK_UP = 1,
	EVT_NO_MEDIA = 2,
	EVT_LINK_FAULT = 3,
	EVT_PHY_TEMP_ALARM = 4,
	EVT_EXCESSIVE_ERRORS = 5,
	EVT_SIGNAL_DETECT = 6,
	EVT_AUTO_NEGOTIATION_DONE = 7,
	EVT_MODULE_QUALIFICATION_FAILD = 8,
	EVT_PORT_TX_SUSPEND = 9,
};

enum pma_type {
	PHY_TYPE_NONE = 0,
	PHY_TYPE_1G_BASE_KX,
	PHY_TYPE_SGMII,
};

struct phy_abilities {
	u8 link_stat;
	u8 lane_mask;
	__le32 speed;
	__le16 phy_type;
	__le16 nic_mode;
	__le16 pfnum;
	__le32 fw_version;
	__le32 axi_mhz;
	union {
		u8 port_id[4];
		__le32 port_ids;
	};
	__le32 bd_uid;
	__le32 phy_id;
	__le32 wol_status;
	union {
		__le32 ext_ablity;
		struct {
			u32 valid : 1;
			u32 wol_en : 1;
			u32 pci_preset_runtime_en : 1;
			u32 smbus_en : 1;
			u32 ncsi_en : 1;
			u32 rpu_en : 1;
			u32 v2 : 1;
			u32 pxe_en : 1;
			u32 mctp_en : 1;
			u32 yt8614 : 1;
			u32 pci_ext_reset : 1;
			u32 rpu_availble : 1;
			u32 fw_lldp_ablity : 1;
			u32 lldp_enabled : 1;
			u32 only_1g : 1;
			u32 force_down_en: 1;
		} e;
	};
} __packed;

static inline void ability_update_host_endian(struct phy_abilities *abi)
{
	u32 host_val = le32_to_cpu(abi->ext_ablity);

	memcpy(&abi->e, &host_val, sizeof(abi->e));
}

enum PHY_INTERFACE {
	PHY_INTERNAL_PHY = 0,
	PHY_EXTERNAL_PHY_MDIO = 1,
};

struct port_stat {
	u8 phyid;
	u8 duplex : 1;
	u8 autoneg : 1;
	u8 fec : 1;
	u16 speed;
	union {
		__le16 stat;
		struct {
			u16 pause : 4;
			u16 local_eee : 3;
			u16 partner_eee : 3;
			u16 tp_mdx : 2;
			u16 lldp_status : 1;
			u16 revs : 3;
		} v_host;
	};
} __packed;

static inline void port_stat_update_host_endian(struct port_stat *stat)
{
	u16 host_val = le16_to_cpu(stat->stat);

	stat->v_host = *(typeof(stat->v_host) *)&host_val;
}

struct phy_pause_data {
	__le32 pause_mode;
} __packed;

struct lane_stat_data {
	u8 nr_lane;
	u8 pci_gen : 4;
	u8 pci_lanes : 4;
	u8 pma_type;
	u8 phy_type;
	union {
		__le16 link_st;
		struct {
			u16 linkup : 1;
			u16 duplex : 1;
			u16 autoneg : 1;
			u16 fec : 1;
			u16 an : 1;
			u16 link_traing : 1;
			u16 media_availble : 1;
			u16 is_sgmii : 1;
			u16 link_fault : 4;
#define LINK_LINK_FAULT BIT(0)
#define LINK_TX_FAULT BIT(1)
#define LINK_RX_FAULT BIT(2)
#define LINK_REMOTE_FAULT BIT(3)
			u16 is_backplane : 1;
			u16 tp_mdx : 2;
		} st_host;
	};
	union {
		u8 phy_addr;
		struct {
			u8 mod_abs : 1;
			u8 fault : 1;
			u8 tx_dis : 1;
			u8 los : 1;
		} sfp;
	};
	u8 sfp_connector;
	__le32 speed;
	__le32 si_main;
	__le32 si_pre;
	__le32 si_post;
	__le32 si_tx_boost;
	__le32 supported_link;
	__le32 phy_id;
	__le32 advertised_link;
} __packed;

static inline void lane_update_host_endian(struct lane_stat_data *lane)
{
	u16 host_val = le16_to_cpu(lane->link_st);

	lane->st_host = *(typeof(lane->st_host) *)&host_val;
}

/* == flags == */
#define FLAGS_DD BIT(0) /* driver clear 0, FW must set 1 */
#define FLAGS_CMP BIT(1) /* driver clear 0, FW mucst set */
#define FLAGS_ERR                                                              \
	BIT(2) /* driver clear 0, FW must set only if it reporting an error */
#define FLAGS_LB BIT(9)
#define FLAGS_RD BIT(10) /* set if additional buffer has command parameters */
#define FLAGS_BUF BIT(12) /* set 1 on indirect command */
#define FLAGS_SI BIT(13) /* not irq when command complete */
#define FLAGS_EI BIT(14) /* interrupt on error */
#define FLAGS_FE BIT(15) /* flush error */

#ifndef SHM_DATA_MAX_BYTES
#define SHM_DATA_MAX_BYTES (64 - 2 * 4)
#endif

#define MBX_REQ_HDR_LEN 24
#define MBX_REPLYHDR_LEN 16
#define MBX_REQ_MAX_DATA_LEN (SHM_DATA_MAX_BYTES - MBX_REQ_HDR_LEN)
#define MBX_REPLY_MAX_DATA_LEN (SHM_DATA_MAX_BYTES - MBX_REPLYHDR_LEN)

struct mbx_fw_cmd_req {
	__le16 flags; /* 0-1 */
	__le16 opcode; /* 2-3 enum LINK_ADM_CMD */
	__le16 datalen; /* 4-5 */
	__le16 ret_value; /* 6-7 */
	union {
		struct {
			__le32 cookie_lo; /* 8-11 */
			__le32 cookie_hi; /* 12-15 */
		};
		void *cookie;
	};
	__le32 reply_lo; /* 16-19 5dw */
	__le32 reply_hi; /* 20-23 */
	/*=== data === 7dw [24-64] */
	union {
		u8 data[32];
		struct {
			__le32 addr;
			__le32 bytes;
		} r_reg;
		struct {
			__le32 addr;
			__le32 bytes;
			__le32 data[4];
		} w_reg;
		struct {
			__le32 lane;
			__le32 up;
		} ifup;
		struct {
			__le32 sec;
			__le32 nanosec;
		} tstamps;
		struct {
			__le32 lane;
			__le32 status;
		} ifinsmod;
		struct {
			__le32 lane;
			__le32 status;
		} ifforce;
		struct {
			__le32 lane;
			__le32 status;
		} ifsuspuse;
		struct {
			__le32 nr_lane;
		} get_lane_st;
		struct {
			__le32 flag;
			__le32 nr_lane;
		} set_dump;
		struct {
			__le32 lane;
			__le32 enable;
		} wol;
		struct {
			__le32 lane;
			__le32 mode;
		} gephy_test;
		struct {
			__le32 lane;
			__le32 op;
			__le32 enable;
			__le32 interval;
		} lldp_tx;
		struct {
			__le32 bytes;
			__le32 nr_lane;
			__le32 bin_offset;
			__le32 no_use;
		} get_dump;
		struct {
			__le32 nr_lane;
			__le32 value;
#define LED_IDENTIFY_INACTIVE 0
#define LED_IDENTIFY_ACTIVE 1
#define LED_IDENTIFY_ON 2
#define LED_IDENTIFY_OFF 3
		} led_set;
		struct {
			__le32 addr;
			__le32 data;
			__le32 mask;
		} modify_reg;
		struct {
			__le32 adv_speed_mask;
			__le32 autoneg;
			__le32 speed;
			__le32 duplex;
			__le32 nr_lane;
			__le32 tp_mdix_ctrl;
		} phy_link_set;
		struct {
			__le32 pause_mode;
			__le32 nr_lane;
		} phy_pause_set;
		struct {
			__le32 pause_mode;
			__le32 nr_lane;
		} phy_pause_get;
		struct {
			__le32 local_eee;
			__le32 tx_lpi_timer;
			__le32 nr_lane;
		} phy_eee_set;
		struct {
			__le32 nr_lane;
			__le32 sfp_adr; /* 0xa0 or 0xa2 */
			__le32 reg;
			__le32 cnt;
		} sfp_read;
		struct {
			__le32 nr_lane;
			__le32 sfp_adr; /* 0xa0 or 0xa2 */
			__le32 reg;
			__le32 val;
		} sfp_write;
		struct {
			__le16 changed_lanes;
			__le16 lane_status;
			__le32 port_st_magic;
#define SPEED_VALID_MAGIC 0xa4a6a8a9
			struct port_stat st[4];
		} link_stat; /* FW->RC */
		struct {
			__le16 enable_stat;
			__le16 event_mask;
		} stat_event_mask;
		struct {
			__le32 cmd;
			__le32 arg0;
			__le32 req_bytes;
			__le32 reply_bytes;
			__le32 ddr_lo;
			__le32 ddr_hi;
		} maintain;
		struct {
			__le32 lane_mask;
			__le32 pfvf_num;
		} get_mac_addr;
		struct {
			u8 paration;
			__le32 bytes;
			__le32 bin_phy_lo;
			__le32 bin_phy_hi;
		} fw_update;
	};
} __packed;

#define EEE_1000BT BIT(2)
#define EEE_100BT BIT(1)

struct rnpgbe_eee_cap {
	__le32 local_capability;
	__le32 local_eee;
	__le32 partner_eee;
};

/* firmware -> driver */
struct mbx_fw_cmd_reply {
	/* fw must set: DD, CMP, Error(if error), copy value */
	__le16 flags;
	/* from command: LB,RD,VFC,BUF,SI,EI,FE */
	__le16 opcode; /* 2-3: copy from req */
	__le16 error_code; /* 4-5: 0 if no error */
	__le16 datalen; /* 6-7: */
	union {
		struct {
			__le32 cookie_lo; /* 8-11: */
			__le32 cookie_hi; /* 12-15: */
		};
		void *cookie;
	};
	/* ===== data ==== [16-64] */
	union {
		u8 data[40];
		struct version {
			__le32 major;
			__le32 sub;
			__le32 modify;
		} version;
		struct {
			__le32 value[4];
		} r_reg;
		struct {
			__le32 new_value;
		} modify_reg;
		struct get_temp {
			__le32 temp;
			__le32 voltage;
		} get_temp;
		struct {
#define MBX_SFP_READ_MAX_CNT 32
			u8 value[MBX_SFP_READ_MAX_CNT];
		} sfp_read;
		struct mac_addr {
			__le32 lanes;
			struct _addr {
				/*
				 * for macaddr:01:02:03:04:05:06
				 * mac-hi=0x01020304 mac-lo=0x05060000
				 */
				u8 mac[8];
			} addrs[4];
		} mac_addr;
		struct get_dump_reply {
			__le32 flags;
			__le32 version;
			__le32 bytes;
			__le32 data[4];
		} get_dump;
		struct get_lldp_reply {
			__le32 value;
			__le32 interval;
		} get_lldp;
		struct rnpgbe_eee_cap phy_eee_abilities;
		struct lane_stat_data lanestat;
		struct phy_abilities phy_abilities;
	};
} __packed __aligned(4);

static inline void build_maintain_req(struct mbx_fw_cmd_req *req, void *cookie,
				      int cmd, int arg0, int req_bytes,
				      int reply_bytes, u32 dma_phy_lo,
				      u32 dma_phy_hi)
{
	req->flags = 0;
	req->opcode = cpu_to_le16(FW_MAINTAIN);
	req->datalen = cpu_to_le16(sizeof(req->maintain));
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->maintain.cmd = cpu_to_le32(cmd);
	req->maintain.arg0 = cpu_to_le32(arg0);
	req->maintain.req_bytes = cpu_to_le32(req_bytes);
	req->maintain.reply_bytes = cpu_to_le32(reply_bytes);
	req->maintain.ddr_lo = cpu_to_le32(dma_phy_lo);
	req->maintain.ddr_hi = cpu_to_le32(dma_phy_hi);
}

static inline void build_fw_update_gbe_req(struct mbx_fw_cmd_req *req,
					   void *cookie, int partition,
					   int fw_bytes)
{
	req->flags = 0;
	req->opcode = cpu_to_le16(FW_UPDATE_GBE);
	req->datalen = cpu_to_le16(sizeof(req->fw_update));
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->fw_update.paration = partition;
	req->fw_update.bytes = cpu_to_le32(fw_bytes);
}

static inline void build_reset_phy_req(struct mbx_fw_cmd_req *req, void *cookie)
{
	req->flags = 0;
	req->opcode = cpu_to_le16(RESET_PHY);
	req->datalen = 0;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->cookie = cookie;
}

static inline void build_phy_eee_abalities_req(struct mbx_fw_cmd_req *req,
					       void *cookie)
{
	req->flags = 0;
	req->opcode = cpu_to_le16(PHY_EEE_GET);
	req->datalen = 0;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->cookie = cookie;
}

static inline void build_phy_abalities_req(struct mbx_fw_cmd_req *req)
{
	req->flags = 0;
	req->opcode = cpu_to_le16(GET_PHY_ABALITY);
	req->datalen = 0;
	req->reply_lo = 0;
	req->reply_hi = 0;
	//req->cookie = cookie;
}

static inline void build_get_macaddress_req(struct mbx_fw_cmd_req *req,
					    int lane_mask, int pfvfnum,
					    void *cookie)
{
	req->flags = 0;
	req->opcode = cpu_to_le16(GET_MAC_ADDRES);
	req->datalen = cpu_to_le16(sizeof(req->get_mac_addr));
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->get_mac_addr.lane_mask = cpu_to_le32(lane_mask);
	req->get_mac_addr.pfvf_num = cpu_to_le32(pfvfnum);
}

static inline void build_version_req(struct mbx_fw_cmd_req *req, void *cookie)
{
	req->flags = 0;
	req->opcode = cpu_to_le16(GET_VERSION);
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->datalen = 0;
	req->cookie = cookie;
}

static inline void build_readreg_req(struct mbx_fw_cmd_req *req, int reg_addr,
				     void *cookie)
{
	req->flags = 0;
	req->opcode = cpu_to_le16(READ_REG);
	req->datalen = cpu_to_le16(sizeof(req->r_reg));
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->r_reg.addr = cpu_to_le32(reg_addr & ~(3));
	req->r_reg.bytes = cpu_to_le32(4);
}

static inline void mbx_fw_req_set_reply(struct mbx_fw_cmd_req *req,
					dma_addr_t reply)
{
	u64 address = reply;

	req->reply_hi = cpu_to_le32(address >> 32);
	req->reply_lo = cpu_to_le32((address) & 0xffffffff);
}

static inline void build_writereg_req(struct mbx_fw_cmd_req *req, void *cookie,
				      int reg_addr, int bytes, int value[4])
{
	int i;

	req->flags = 0;
	req->opcode = cpu_to_le16(WRITE_REG);
	req->datalen = cpu_to_le16(sizeof(req->w_reg));
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->w_reg.addr = cpu_to_le32(reg_addr & ~3);
	req->w_reg.bytes = cpu_to_le32(bytes);
	for (i = 0; i < bytes / 4; i++)
		req->w_reg.data[i] = cpu_to_le32(value[i]);
}

static inline void build_modifyreg_req(struct mbx_fw_cmd_req *req, void *cookie,
				       int reg_addr, int value,
				       unsigned int mask)
{
	req->flags = 0;
	req->opcode = cpu_to_le16(MODIFY_REG);
	req->datalen = cpu_to_le16(sizeof(req->modify_reg));
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->modify_reg.addr = cpu_to_le32(reg_addr);
	req->modify_reg.data = cpu_to_le32(value);
	req->modify_reg.mask = cpu_to_le32(mask);
}

static inline void build_get_lane_status_req(struct mbx_fw_cmd_req *req,
					     int nr_lane, void *cookie)
{
	req->flags = 0;
	req->opcode = cpu_to_le16(GET_LANE_STATUS);
	req->datalen = cpu_to_le16(sizeof(req->get_lane_st));
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->get_lane_st.nr_lane = cpu_to_le32(nr_lane);
}

static inline void build_get_temp(struct mbx_fw_cmd_req *req, void *cookie)
{
	req->flags = 0;
	req->opcode = cpu_to_le16(GET_TEMP);
	req->datalen = 0;
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
}

static inline void build_get_dump_req(struct mbx_fw_cmd_req *req, void *cookie,
				      int nr_lane, u32 fw_bin_phy_lo,
				      u32 fw_bin_phy_hi, int bytes)
{
	req->flags = 0;
	req->opcode = cpu_to_le16(GET_DUMP);
	req->datalen = cpu_to_le16(sizeof(req->get_dump));
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->get_dump.bytes = cpu_to_le32(bytes);
	req->get_dump.nr_lane = cpu_to_le32(nr_lane);
	req->get_dump.bin_offset = cpu_to_le32(fw_bin_phy_lo);
	req->get_dump.no_use = cpu_to_le32(fw_bin_phy_hi);
}

static inline void build_set_dump(struct mbx_fw_cmd_req *req, int nr_lane,
				  int flag)
{
	req->flags = 0;
	req->opcode = cpu_to_le16(SET_DUMP);
	req->datalen = cpu_to_le16(sizeof(req->set_dump));
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->set_dump.flag = cpu_to_le32(flag);
	req->set_dump.nr_lane = cpu_to_le32(nr_lane);
}

static inline void build_led_set(struct mbx_fw_cmd_req *req,
				 unsigned int nr_lane, int value, void *cookie)
{
	req->flags = 0;
	req->opcode = cpu_to_le16(LED_SET);
	req->datalen = cpu_to_le16(sizeof(req->led_set));
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->led_set.nr_lane = cpu_to_le32(nr_lane);
	req->led_set.value = cpu_to_le32(value);
}

static inline void build_phy_pause_set(struct mbx_fw_cmd_req *req,
				       int pause_mode, int nr_lane)
{
	req->flags = 0;
	req->opcode = cpu_to_le16(PHY_PAUSE_SET);
	req->datalen = cpu_to_le16(sizeof(req->phy_pause_set));
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->phy_pause_set.nr_lane = cpu_to_le32(nr_lane);
	req->phy_pause_set.pause_mode = cpu_to_le32(pause_mode);
}

static inline void build_get_phy_pause_req(struct mbx_fw_cmd_req *req,
					   int nr_lane, void *cookie)
{
	req->flags = 0;
	req->opcode = cpu_to_le16(PHY_PAUSE_GET);
	req->datalen = cpu_to_le16(sizeof(req->phy_pause_get));
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->phy_pause_set.nr_lane = cpu_to_le32(nr_lane);
	req->phy_pause_set.pause_mode = 0;
}

static inline void build_phy_eee_set(struct mbx_fw_cmd_req *req, u32 local_eee,
				     u32 tx_lpi_timer, int nr_lane)
{
	req->flags = 0;
	req->opcode = cpu_to_le16(PHY_EEE_SET);
	req->datalen = cpu_to_le16(sizeof(req->phy_eee_set));
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->phy_eee_set.nr_lane = cpu_to_le32(nr_lane);
	req->phy_eee_set.local_eee = cpu_to_le32(local_eee);
	req->phy_eee_set.tx_lpi_timer = cpu_to_le32(tx_lpi_timer);
}

static inline void build_phy_link_set(struct mbx_fw_cmd_req *req,
				      unsigned int adv, int nr_lane,
				      unsigned int autoneg, unsigned int speed,
				      unsigned int duplex,
				      unsigned int tp_mdix_ctrl)
{
	req->flags = 0;
	req->opcode = cpu_to_le16(PHY_LINK_SET);
	req->datalen = cpu_to_le16(sizeof(req->phy_link_set));
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->phy_link_set.nr_lane = cpu_to_le32(nr_lane);
	req->phy_link_set.adv_speed_mask = cpu_to_le32(adv);
	req->phy_link_set.autoneg = cpu_to_le32(autoneg);
	req->phy_link_set.speed = cpu_to_le32(speed);
	req->phy_link_set.duplex = cpu_to_le32(duplex);
	req->phy_link_set.tp_mdix_ctrl = cpu_to_le32(tp_mdix_ctrl);
}

static inline void build_tstamp_show(struct mbx_fw_cmd_req *req, u32 sec,
				     u32 nanosec)
{
	req->flags = 0;
	req->opcode = cpu_to_le16(SHOW_TX_STAMP);
	req->datalen = cpu_to_le16(sizeof(req->tstamps));
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->tstamps.sec = cpu_to_le32(sec);
	req->tstamps.nanosec = cpu_to_le32(nanosec);
}

static inline void build_ifup_down(struct mbx_fw_cmd_req *req,
				   unsigned int nr_lane, int up)
{
	req->flags = 0;
	req->opcode = cpu_to_le16(IFUP_DOWN);
	req->datalen = cpu_to_le16(sizeof(req->ifup));
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->ifup.lane = cpu_to_le32(nr_lane);
	req->ifup.up = cpu_to_le32(up);
}

static inline void build_ifinsmod(struct mbx_fw_cmd_req *req,
				  unsigned int nr_lane, int status)
{
	req->flags = 0;
	req->opcode = cpu_to_le16(DRIVER_INSMOD);
	req->datalen = cpu_to_le16(sizeof(req->ifinsmod));
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->ifinsmod.lane = cpu_to_le32(nr_lane);
	req->ifinsmod.status = cpu_to_le32(status);
}

static inline void build_ifsuspuse(struct mbx_fw_cmd_req *req,
				   unsigned int nr_lane, int status)
{
	req->flags = 0;
	req->opcode = cpu_to_le16(SYSTEM_SUSPUSE);
	req->datalen = cpu_to_le16(sizeof(req->ifsuspuse));
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->ifsuspuse.lane = cpu_to_le32(nr_lane);
	req->ifsuspuse.status = cpu_to_le32(status);
}

static inline void build_ifforce(struct mbx_fw_cmd_req *req,
				 unsigned int nr_lane, int status)
{
	req->flags = 0;
	req->opcode = cpu_to_le16(SYSTEM_FORCE);
	req->datalen = cpu_to_le16(sizeof(req->ifforce));
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->ifforce.lane = cpu_to_le32(nr_lane);
	req->ifforce.status = cpu_to_le32(status);
}

static inline void build_mbx_sfp_read(struct mbx_fw_cmd_req *req,
				      unsigned int nr_lane, int sfp_addr,
				      int reg, int cnt, void *cookie)
{
	req->flags = 0;
	req->opcode = cpu_to_le16(SFP_MODULE_READ);
	req->datalen = cpu_to_le16(sizeof(req->sfp_read));
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->sfp_read.nr_lane = cpu_to_le32(nr_lane);
	req->sfp_read.sfp_adr = cpu_to_le32(sfp_addr);
	req->sfp_read.reg = cpu_to_le32(reg);
	req->sfp_read.cnt = cpu_to_le32(cnt);
}

static inline void build_mbx_sfp_write(struct mbx_fw_cmd_req *req,
				       unsigned int nr_lane, int sfp_addr,
				       int reg, int v)
{
	req->flags = 0;
	req->opcode = cpu_to_le16(SFP_MODULE_WRITE);
	req->datalen = cpu_to_le16(sizeof(req->sfp_write));
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->sfp_write.nr_lane = cpu_to_le32(nr_lane);
	req->sfp_write.sfp_adr = cpu_to_le32(sfp_addr);
	req->sfp_write.reg = cpu_to_le32(reg);
	req->sfp_write.val = cpu_to_le32(v);
}

static inline void build_mbx_wol_set(struct mbx_fw_cmd_req *req,
				     unsigned int nr_lane, u32 mode)
{
	req->flags = 0;
	req->opcode = cpu_to_le16(SET_WOL);
	req->datalen = cpu_to_le16(sizeof(req->sfp_write));
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->wol.lane = cpu_to_le32(nr_lane);
	req->wol.enable = cpu_to_le32(mode);
}

static inline void build_mbx_gephy_test_set(struct mbx_fw_cmd_req *req,
					    unsigned int nr_lane, u32 mode)
{
	req->flags = 0;
	req->opcode = cpu_to_le16(SET_TEST_MODE);
	req->datalen = cpu_to_le16(sizeof(req->sfp_write));
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->gephy_test.lane = cpu_to_le32(nr_lane);
	req->gephy_test.mode = cpu_to_le32(mode);
}

static inline void build_get_lldp_req(struct mbx_fw_cmd_req *req, void *cookie,
				      int nr_lane)
{
#define LLDP_TX_GET (1)

	req->flags = 0;
	req->opcode = cpu_to_le16(LLDP_TX_CTRL);
	req->datalen = cpu_to_le16(sizeof(req->lldp_tx));
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->lldp_tx.lane = cpu_to_le32(nr_lane);
	req->lldp_tx.op = cpu_to_le32(LLDP_TX_GET);
	req->lldp_tx.enable = 0;
}

static inline void build_mbx_lldp_set(struct mbx_fw_cmd_req *req,
				      unsigned int nr_lane, u32 enable)
{
#define LLDP_TX_SET (0)
	req->flags = 0;
	req->opcode = cpu_to_le16(LLDP_TX_CTRL);
	req->datalen = cpu_to_le16(sizeof(req->sfp_write));
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->lldp_tx.lane = cpu_to_le32(nr_lane);
	req->lldp_tx.op = cpu_to_le32(LLDP_TX_SET);
	req->lldp_tx.enable = cpu_to_le32(enable);
	req->lldp_tx.interval = cpu_to_le32(30);
}

static inline void build_link_set_event_mask(struct mbx_fw_cmd_req *req,
					     u16 event_mask,
					     u16 enable,
					     void *cookie)
{
	req->flags = 0;
	req->opcode = cpu_to_le16(SET_EVENT_MASK);
	req->datalen = cpu_to_le16(sizeof(req->stat_event_mask));
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->stat_event_mask.event_mask = cpu_to_le16(event_mask);
	req->stat_event_mask.enable_stat = cpu_to_le16(enable);
}

enum MBX_ERR {
	MBX_OK = 0,
	MBX_ERR_NO_PERM,
	MBX_ERR_INVAL_OPCODE,
	MBX_ERR_INVALID_PARAM,
	MBX_ERR_INVALID_ADDR,
	MBX_ERR_INVALID_LEN,
	MBX_ERR_NODEV,
	MBX_ERR_IO,
};

int rnpgbe_fw_get_capability(struct rnpgbe_hw *hw, struct phy_abilities *abil);
#endif /* _RNPGBE_MBX_FW_H */
