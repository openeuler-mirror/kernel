/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSEVF_TYPE_H_
#define _NSEVF_TYPE_H_

#include <linux/stddef.h>

#include "nsevf_status.h"
#include "nsevf_osdep.h"
#include "siov_regs.h"
#include "nsevf_hw_reg.h"
#include "nsevf_adminq.h"
#include "nsevf_devids.h"

#define NSEVF_RXQ_CTX_DBUFF_SHIFT 7

/* NSEVF_MASK is a macro used on 32 bit registers */
#define NSEVF_MASK(mask, shift) ((mask) << (shift))

#define NSEVF_MAX_VSI_QP 16
#define NSEVF_MAX_CHAINED_RX_BUFFERS 5

/* forward declaration */
struct nsevf_hw;
typedef void (*NSEVF_ADMINQ_CALLBACK)(struct nsevf_hw *,
				      struct nsevf_aq_desc *);

/* Data type manipulation macros. */

#define NSEVF_DESC_UNUSED(R)                                          \
	((((R)->next_to_clean > (R)->next_to_use) ? 0 : (R)->count) + \
	 (R)->next_to_clean - (R)->next_to_use - 1)

/* bitfields for Tx queue mapping in QTX_CTL */
#define NSEVF_QTX_CTL_VF_QUEUE 0x0
#define NSEVF_QTX_CTL_VM_QUEUE 0x1
#define NSEVF_QTX_CTL_PF_QUEUE 0x2

/* debug masks - set these bits in hw->debug_mask to control output */
#define NSEVF_DBG_SYS BIT_ULL(1)
#define NSEVF_DBG_MISC BIT_ULL(2)
#define NSEVF_DBG_FW BIT_ULL(3)
#define NSEVF_DBG_LMAC_PHY BIT_ULL(4)
#define NSEVF_DBG_LAN BIT_ULL(5)
#define NSEVF_DBG_DCB BIT_ULL(6)
#define NSEVF_DBG_SCHED BIT_ULL(7)
#define NSEVF_DBG_RCF BIT_ULL(8)
#define NSEVF_DBG_PTP BIT_ULL(9)
#define NSEVF_DBG_SW BIT_ULL(10)
#define NSEVF_DBG_RDMA BIT_ULL(11)
#define NSEVF_DBG_NVM BIT_ULL(12)

#define NSEVF_DBG_AQM_MSG BIT_ULL(27)
#define NSEVF_DBG_AQM_DESC BIT_ULL(28)
#define NSEVF_DBG_AQM_BUF BIT_ULL(29)
#define NSEVF_DBG_AQM_ALL \
	(NSEVF_DBG_AQM_MSG | NSEVF_DBG_AQM_DESC | NSEVF_DBG_AQM_BUF)

#define NSEVF_DBG_USER BIT_ULL(31)
#define NSEVF_DBG_ALL 0xFFFFFFFFFFFFFFFFULL

/* These are structs for managing the hardware information and the operations.
 * The structures of function pointers are filled out at init time when we
 * know for sure exactly which hardware we're working with.  This gives us the
 * flexibility of using the same main driver code but adapting to slightly
 * different hardware needs as new parts are developed.  For this architecture,
 * the Firmware and AdminQ are intended to insulate the driver from most of the
 * future changes, but these structures will also do part of the job.
 */
enum nsevf_mac_type {
	NSEVF_MAC_UNKNOWN = 0,
	NSEVF_MAC_VF,
};

enum nsevf_pf_mac_type { /* pf nse_mac_type */
			 NSEVF_PF_MAC_TYPE_UNKNOWN = 0,
			 NSEVF_PF_MAC_TYPE_AMBER,
			 NSEVF_PF_MAC_TYPE_MOONSTONE,
};

enum nsevf_vsi_type {
	NSEVF_VSI_MAIN = 0,
	NSEVF_VSI_VMDQ1 = 1,
	NSEVF_VSI_VMDQ2 = 2,
	NSEVF_VSI_CTRL = 3,
	NSEVF_VSI_FCOE = 4,
	NSEVF_VSI_MIRROR = 5,
	NSEVF_VSI_SRIOV = 6,
	NSEVF_VSI_TYPE_UNKNOWN
};

enum nsevf_queue_type {
	NSEVF_QUEUE_TYPE_RX = 0,
	NSEVF_QUEUE_TYPE_TX,
	NSEVF_QUEUE_TYPE_PE_CEQ,
	NSEVF_QUEUE_TYPE_UNKNOWN
};

/* Capabilities of a PF or a VF or the whole device */
struct nsevf_hw_capabilities {
	bool dcb; /* xzhao: don't misunderstand, this field is not used, it is not DCB */
	bool fcoe;
	bool iwarp;
	u32 num_vsis;
	u32 num_rx_qp;
	u32 num_tx_qp;
	u32 base_queue;
	u32 num_msix_vectors_vf;
	u32 max_mtu;
	u16 lan_txcq_base_abs_id;
	u16 lan_txcq_num;

	u16 lan_rxq_base_abs_id;
};

struct nsevf_mac_info {
	enum nsevf_mac_type type;
	enum nsevf_pf_mac_type pf_mac_type;
	u8 addr[ETH_ALEN];
	u8 perm_addr[ETH_ALEN];
	u8 san_addr[ETH_ALEN];
	u8 port_addr[ETH_ALEN];
	u16 max_fcoeq;
};

/* PCI bus types */
enum nsevf_bus_type {
	nsevf_bus_type_unknown = 0,
	nsevf_bus_type_pci,
	nsevf_bus_type_pcix,
	nsevf_bus_type_pci_express,
	nsevf_bus_type_reserved
};

/* PCI bus speeds */
enum nsevf_bus_speed {
	nsevf_bus_speed_unknown = 0,
	nsevf_bus_speed_33 = 33,
	nsevf_bus_speed_66 = 66,
	nsevf_bus_speed_100 = 100,
	nsevf_bus_speed_120 = 120,
	nsevf_bus_speed_133 = 133,
	nsevf_bus_speed_2500 = 2500,
	nsevf_bus_speed_5000 = 5000,
	nsevf_bus_speed_8000 = 8000,
	nsevf_bus_speed_reserved
};

/* PCI bus widths */
enum nsevf_bus_width {
	nsevf_bus_width_unknown = 0,
	nsevf_bus_width_pcie_x1 = 1,
	nsevf_bus_width_pcie_x2 = 2,
	nsevf_bus_width_pcie_x4 = 4,
	nsevf_bus_width_pcie_x8 = 8,
	nsevf_bus_width_32 = 32,
	nsevf_bus_width_64 = 64,
	nsevf_bus_width_reserved
};

/* Bus parameters */
struct nsevf_bus_info {
	enum nsevf_bus_speed speed;
	enum nsevf_bus_width width;
	enum nsevf_bus_type type;

	u16 func;
	u16 device;
	u16 lan_id;
	u16 bus_id;
};

#define NSEVF_MAX_USER_PRIORITY 8
#define NSEVF_TLV_STATUS_OPER 0x1
#define NSEVF_TLV_STATUS_SYNC 0x2
#define NSEVF_TLV_STATUS_ERR 0x4
#define NSEVF_CEE_OPER_MAX_APPS 3
#define NSEVF_APP_PROTOID_FCOE 0x8906
#define NSEVF_APP_PROTOID_ISCSI 0x0cbc
#define NSEVF_APP_PROTOID_FIP 0x8914
#define NSEVF_APP_SEL_ETHTYPE 0x1
#define NSEVF_APP_SEL_TCPIP 0x2
#define NSEVF_CEE_APP_SEL_ETHTYPE 0x0
#define NSEVF_CEE_APP_SEL_TCPIP 0x1

/* Port hardware description */
struct nsevf_hw {
	u8 __iomem *hw_addr;
	void *back;

	/* subsystem structs */
	struct nsevf_mac_info mac;
	struct nsevf_bus_info bus;

	/* pci info */
	u16 device_id;
	u16 vendor_id;
	u16 subsystem_device_id;
	u16 subsystem_vendor_id;
	u8 revision_id;

	/* capabilities for entire device and PCI func */
	struct nsevf_hw_capabilities dev_caps;

	/* mailbox Queue info */
	struct nsevf_ctl_q_info mailboxq;

	struct nsevf_ctl_q_info utilq;
	bool utilq_initialized;

#define NSE_ITR_GRAN_FIXED 2
	u8 itr_gran;
#define NSE_INTRL_GRAN_FIXED 4
	u8 intrl_gran;

	/* debug mask */
	u64 debug_mask;
	char err_str[16];

	struct {
		u64 sq_total_cnt;
		u64 sq_success_cnt;
		u64 sq_fail_cnt;
		u64 sq_fail_timeout_cnt;

		u64 sq_total_ns;
		u64 sq_success_ns;
		u64 sq_fail_ns;
		u64 sq_fail_timeout_ns;

		u64 sq_total_wait_cnt;

		u64 mq_cmd_shutdown_time;
		u64 mq_cmd_shutdown_cnt;

		u64 mq_sq_wait_for_fw_pause_disable_fail_cnt;
		u64 mq_sq_wait_for_fw_pause_disable_fail_time;

		u64 mq_sq_wait_for_sw_pause_fail_cnt;
		u64 mq_sq_wait_for_sw_pause_fail_time;

		u64 mq_sq_wait_for_sw_disable_fail_cnt;
		u64 mq_sq_wait_for_sw_disable_fail_time;

		u64 mq_rq_wait_for_fw_pause_disable_fail_cnt;
		u64 mq_rq_wait_for_fw_pause_disable_fail_time;

		u64 mq_rq_wait_for_sw_pause_fail_cnt;
		u64 mq_rq_wait_for_sw_pause_fail_time;

		u64 mq_rq_wait_for_sw_disable_fail_cnt;
		u64 mq_rq_wait_for_sw_disable_fail_time;
	} controlq_stats;

	struct work_struct aq_cmd_background_task;
	unsigned int aq_cmd_background_task_busy; /* work_busy() */
	/* 0: cancel, 1: version, 2: get configuration. */
	unsigned int aq_cmd_background_task_cmd_type;
	unsigned int aq_cmd_background_task_cmd_cnt;
	unsigned int aq_cmd_background_task_cmd_cnt_count_down;

	unsigned int aq_cmd_background_task_cmd_period;

	unsigned int aq_cmd_background_task_cancelling;
};

union nse_32b_rx_desc {
	struct {
		__le64 pkt_addr; /* Packet buffer address */
		__le64 hdr_addr; /* Header buffer address */
		/* bit 0 of hdr_addr is DD bit */
		__le64 rsvd1;
		__le64 rsvd2;
	} read;
	struct {
		/* Word 0 */
		u8 rxdid; /* RXDID: 4 b rsv: 4 b */

		/* Q_src:2, Src_port:2, Md0_vld:1, Md1_vld:1, reserved:2. */
		u8 qsrc_sport_md01valid;
#define NSE_RXD_QSRC_S 0
#define NSE_RXD_QSRC_M NSE_M(0x3, 0)

#define NSE_RXD_QSRC_SW 0x0
#define NSE_RXD_QSRC_ACL 0x1
#define NSE_RXD_QSRC_FD 0x2
#define NSE_RXD_QSRC_RSS 0x3

#define NSE_RXD_SPORT_S 2
#define NSE_RXD_SPORT_M NSE_M(0x3, 2)

#define NSE_RXD_SPORT_LAN 0x0
#define NSE_RXD_SPORT_LOOPBACK 0x1
#define NSE_RXD_SPORT_BMC 0x2
#define NSE_RXD_SPORT_MNG 0x3

#define NSE_RXD_MD0_VALID_S 4
#define NSE_RXD_MD0_VALID_M BIT(4)

#define NSE_RXD_MD1_VALID_S 5
#define NSE_RXD_MD1_VALID_M BIT(5)

		/* Word 1 */
		__le16 l2tag1_nextp; /* L2TAG1: 16 b, OR: NEXTP: 16 b*/

		/* Word 2 */
		__le16 md0; /* FlexiMD.0: 16 b*/

		/* Word 3 */
		__le16 md1; /* FlexiMD.1: 16 b*/

		/* Word 4 */
		__le16 status_error0;
#define NSE_RXD_STATUS0_DD_S 0
#define NSE_RXD_STATUS0_DD_M BIT(0)

#define NSE_RXD_STATUS0_EOP_S 1
#define NSE_RXD_STATUS0_EOP_M BIT(1)

#define NSE_RXD_STATUS0_HBO_S 2
#define NSE_RXD_STATUS0_HBO_M BIT(2)

#define NSE_RXD_STATUS0_EIPV6EX_S 3
#define NSE_RXD_STATUS0_EIPV6EX_M BIT(3)

#define NSE_RXD_STATUS0_XSUM_IPE_S 4
#define NSE_RXD_STATUS0_XSUM_IPE_M BIT(4)

#define NSE_RXD_STATUS0_XSUM_L4E_S 5
#define NSE_RXD_STATUS0_XSUM_L4E_M BIT(5)

#define NSE_RXD_STATUS0_XSUM_EIPE_S 6
#define NSE_RXD_STATUS0_XSUM_EIPE_M BIT(6)

#define NSE_RXD_STATUS0_XSUM_EUDPE_S 7
#define NSE_RXD_STATUS0_XSUM_EUDPE_M BIT(7)

#define NSE_RXD_STATUS0_MIRR_S 8
#define NSE_RXD_STATUS0_MIRR_M BIT(8)

#define NSE_RXD_STATUS0_IPV6EXADD_S 9
#define NSE_RXD_STATUS0_IPV6EXADD_M BIT(9)

#define NSE_RXD_STATUS0_RXE_S 10
#define NSE_RXD_STATUS0_RXE_M BIT(10)

#define NSE_RXD_STATUS0_CRCP_S 11
#define NSE_RXD_STATUS0_CRCP_M BIT(11)

#define NSE_RXD_STATUS0_PTP_S 12
#define NSE_RXD_STATUS0_PTP_M BIT(12)

#define NSE_RXD_STATUS0_L2TAG1P_S 13
#define NSE_RXD_STATUS0_L2TAG1P_M BIT(13)

#define NSE_RXD_STATUS0_EXT_UDP_0_S 14
#define NSE_RXD_STATUS0_EXT_UDP_0_M BIT(14)

#define NSE_RXD_STATUS0_INT_UDP_0_S 15
#define NSE_RXD_STATUS0_INT_UDP_0_M BIT(15)

		/* Word 5 */
		u8 ptype; /* PTYPE: 8 b */

		u8 misc; /* rsv: 1b, Fdir_err: 3 b, lksec: 1 b, secerr: 2b, sni: 1b */
#define NSE_RXD_FDIR_ERR_S 1
#define NSE_RXD_FDIR_ERR_M NSE_M(0x7, 1)

#define NSE_RXD_LKSEC_S 4
#define NSE_RXD_LKSEC_M BIT(4)

#define NSE_RXD_SECERR_S 5
#define NSE_RXD_SECERR_M NSE_M(0x3, 5)

#define NSE_RXD_SECERR_NO_ERROR 0x0
#define NSE_RXD_SECERR_NO_SA 0x1
#define NSE_RXD_SECERR_REPLAY_ERROR 0x2
#define NSE_RXD_SECERR_ICV_ERROR 0x3

#define NSE_RXD_SNI_S 7
#define NSE_RXD_SNI_M BIT(7)

		/* Word 6 */
		__le16 pktlen_sph_reentry; /* Packet Length: 14 b, SPH: 1 b, reentry: 1b */
#define NSE_RXD_PKT_LEN_S 0
#define NSE_RXD_PKT_LEN_M 0x3FFF

#define NSE_RXD_SPH_S 14
#define NSE_RXD_SPH_M BIT(14)

#define NSE_RXD_REENTRY_S 15
#define NSE_RXD_REENTRY_M BIT(15)

		/* Word 7 */
		__le16 hdrlen_rsccnt; /* Header Length: 10 b, Rsccnt: 4 b, rsv: 2b */
#define NSE_RXD_HDR_LEN_S 0
#define NSE_RXD_HDR_LEN_M 0x3FF

#define NSE_RXD_RSCCNT_S 10
#define NSE_RXD_RSCCNT_M NSE_M(0xF, 10)

		/* Word 8 */
		u8 status_error1; /* Status/Error.1: 8 b */
#define NSE_RXD_STATUS1_V6M_S 0
#define NSE_RXD_STATUS1_V6M_M BIT(0)

#define NSE_RXD_STATUS1_TLS_S 1
#define NSE_RXD_STATUS1_TLS_M BIT(1)

#define NSE_RXD_STATUS1_L2TAG2P_S 2
#define NSE_RXD_STATUS1_L2TAG2P_M BIT(2)

#define NSE_RXD_STATUS1_MD2_VALID_S 3
#define NSE_RXD_STATUS1_MD2_VALID_M BIT(3)

#define NSE_RXD_STATUS1_MD3_VALID_S 4
#define NSE_RXD_STATUS1_MD3_VALID_M BIT(4)

#define NSE_RXD_STATUS1_MD4_VALID_S 5
#define NSE_RXD_STATUS1_MD4_VALID_M BIT(5)

#define NSE_RXD_STATUS1_MD5_VALID_S 6
#define NSE_RXD_STATUS1_MD5_VALID_M BIT(6)

#define NSE_RXD_STATUS1_MD6_VALID_S 7
#define NSE_RXD_STATUS1_MD6_VALID_M BIT(7)

		u8 ts_low; /* TS.L: 8 b */

		/* Word 9 */
		__le16 md6; /* FlexMD.6: 16 b */

		/* Word 10, 11*/
		__le16 l2tag2_1st; /* L2TAG2 (1st): 16 b */
		__le16 l2tag2_2nd; /* L2TAG2 (2nd): 16 b */

		/* Word 12, 13 */
		__le16 md2; /* FlexiMD.2: 16 b */
		__le16 md3; /* FlexiMD.3: 16 b*/

		/* Word 14, 15 */
		union {
			struct {
				__le16 md4; /* FlexiMD.4: 16 b */
				__le16 md5; /* FlexiMD.5: 16 b */
			} __packed;
			__le32 ts_high;
		};
	} wb; /* writeback */

} __packed;

enum nse_rxdid {
	NSE_RXDID_FLEX_BLANK = 0,
	NSE_RXDID_FLEX_NIC = 1,
	NSE_RXDID_FLEX_SWITCHDEV = 2,

	NSE_RXDID_MAX = 16,
};

static inline bool nse_rxdid_has_rss_hash(u8 rxdid)
{
	return (rxdid == NSE_RXDID_FLEX_NIC ||
		rxdid == NSE_RXDID_FLEX_SWITCHDEV);
}

/* Rx Flex Descriptor NIC Profile
 * RxDID Profile: NSE_RXDID_FLEX_NIC
 * FlexiMD.0: RSS hash lower 16-bits from POH-MDID
 * FlexiMD.1: RSS hash upper 16-bits from POH-MDID
 * FlexiMD.2: FDir fdir_hash_result 16-bits from POH-MDID
 * FlexiMD.3: FDir fdir_filter_id 16-bits from POH-MDID
 * FlexiMD.4: unused or ts_high word #0
 * FlexiMD.5: unused or ts_high word #0
 * FlexiMD.6: unused
 */
struct nse_32b_rx_desc_nic {
	/* Word 0 */
	u8 rxdid; /* RXDID: 4 b rsv: 4 b */
	u8 qsrc_sport_md01valid; /* Q_src: 2 b, Src_port: 2 b, Md0_vld: 1 b, Md1_vld: 1 b, rsv: 2b*/
	/* Word 1 */
	__le16 l2tag1_nextp; /* L2TAG1: 16 b, OR: NEXTP: 16 b*/

	/* Word 2 - FlexMD.0: RSS hash lower 16-bits from POH-MDID
	 *
	 * Word 3 - FlexMD.1: RSS hash upper 16-bits from POH-MDID
	 **/
	__le32 rss_hash;

	/* Word 4 */
	__le16 status_error0;
	/* Word 5 */
	u8 ptype; /* PTYPE: 8 b */
	u8 misc; /* rsv: 1b, Fdir_err: 3 b, lksec: 1 b, secerr: 2b, sni: 1b */
	/* Word 6 */
	__le16 pktlen_sph_reentry; /* Packet Length: 14 b, SPH: 1 b, reentry: 1b */
	/* Word 7 */
	__le16 hdrlen_rsccnt; /* Header Length: 10 b, Rsccnt: 4 b */
	/* Word 8 */
	u8 status_error1; /* Status/Error.1: 8 b */
	u8 ts_low; /* TS.L: 8 b */
	/* Word 9 */
	__le16 md6; /* FlexMD.6: 16 b */
	/* Word 10, 11*/
	__le16 l2tag2_1st; /* L2TAG2 (1st): 16 b */
	__le16 l2tag2_2nd; /* L2TAG2 (2nd): 16 b */

	/* Word 12 - FlexiMD.2: FDir fdir_hash_result 16-bits from POH-MDID
	 *
	 * Word 13 - FlexiMD.3: FDir fdir_filter_id 16-bits from POH-MDID
	 **/
	__le16 fdir_hash_result;
	__le16 fdir_filter_id;

	/* Word 14, 15 */
	union {
		struct {
			__le16 md4; /* FlexiMD.4: 16 b */
			__le16 md5; /* FlexiMD.5: 16 b */
		} __packed;
		__le32 ts_high;
	};

} __packed;

/* Tx Data Descriptor */
struct nse_tx_desc {
	__le64 buf_addr; /* Address of descriptor's data buf */

	__le64 cmd_type_offset_bsz;
	/* for style unified clearness, intentionally not use GENMASK_ULL */

#define NSE_TXD_DD_S 0
#define NSE_TXD_DD_M BIT_ULL(0)

#define NSE_TXD_DTYPE_S 1
#define NSE_TXD_DTYPE_M BIT_ULL(1)

#define NSE_TXD_L4TYPE_S 2
#define NSE_TXD_L4TYPE_M (0x3ULL << 2)

#define NSE_TXD_L4TYPE_NONE 0x0ULL
#define NSE_TXD_L4TYPE_TCP 0x1ULL
#define NSE_TXD_L4TYPE_SCTP 0x2ULL
#define NSE_TXD_L4TYPE_UDP 0x3ULL

#define NSE_TXD_IIPT_S 4
#define NSE_TXD_IIPT_M (0x3ULL << 4)

#define NSE_TXD_IIPT_NONE 0x0ULL
#define NSE_TXD_IIPT_IPV6 0x1ULL
#define NSE_TXD_IIPT_IPV4_NO_CSUM 0x2ULL
#define NSE_TXD_IIPT_IPV4_CSUM 0x3ULL

#define NSE_TXD_L4LEN_S 6
#define NSE_TXD_L4LEN_M (0xFULL << 6)

#define NSE_TXD_L4LEN_MAX_IN_DWORD 0xF
#define NSE_TXD_L4LEN_MAX_IN_BYTE 0x3C

#define NSE_TXD_EOP_S 10
#define NSE_TXD_EOP_M BIT_ULL(10)

#define NSE_TXD_RS_S 11
#define NSE_TXD_RS_M BIT_ULL(11)

#define NSE_TXD_L4CSUM_S 12
#define NSE_TXD_L4CSUM_M BIT_ULL(12)

/* RSV: 77 - 1b --- previous IL2AG1, now move into tx-context-desc */
#define NSE_TXD_RSV_1_S 13
#define NSE_TXD_RSV_1_M BIT_ULL(13)

#define NSE_TXD_LOCAL_DATA_S 14
#define NSE_TXD_LOCAL_DATA_M BIT_ULL(14)

#define NSE_TXD_CC_S 15
#define NSE_TXD_CC_M BIT_ULL(15)

#define NSE_TXD_TLEN_S 16
#define NSE_TXD_TLEN_M (0x3FFFFULL << 16)

#define NSE_TXD_MACLEN_S 34
#define NSE_TXD_MACLEN_M (0x7FULL << 34)

#define NSE_TXD_CTX_MACLEN_MAX_IN_WORD 0x7F
#define NSE_TXD_CTX_MACLEN_MAX_IN_BYTE 0xFE

#define NSE_TXD_IPLEN_S 41
#define NSE_TXD_IPLEN_M (0x7FULL << 41)

#define NSE_TXD_IPLEN_MAX_IN_DWORD 0x7F
#define NSE_TXD_IPLEN_MAX_IN_BYTE 0x1FC

/* RSV: 113:112 - 2b */
#define NSE_TXD_RSV_2_S 48
#define NSE_TXD_RSV_2_M (0x3ULL << 48)

#define NSE_TXD_BSIZE_S 50
#define NSE_TXD_BSIZE_M (0x3FFFULL << 50)
} __packed;

/* Tx Context Descriptor */
struct nse_tx_ctx_desc {
	__le32 tunneling_params;
#define NSE_TXD_CTX_EIPT_S 0
#define NSE_TXD_CTX_EIPT_M NSE_M(0x3, 0)

#define NSE_TXD_CTX_EIPT_NONE 0x0
#define NSE_TXD_CTX_EIPT_IPV6 0x1
#define NSE_TXD_CTX_EIPT_IPV4_NO_CSUM 0x2
#define NSE_TXD_CTX_EIPT_IPV4_CSUM 0x3

#define NSE_TXD_CTX_EIPLEN_S 2
#define NSE_TXD_CTX_EIPLEN_M NSE_M(0x7F, 2)

#define NSE_TXD_CTX_EIPLEN_MAX_IN_DWORD 0x7F
#define NSE_TXD_CTX_EIPLEN_MAX_IN_BYTE 0x1FC

#define NSE_TXD_CTX_L4TUNT_S 9
#define NSE_TXD_CTX_L4TUNT_M NSE_M(0x3, 9)

#define NSE_TXD_CTX_L4TUNT_NONE 0x0
#define NSE_TXD_CTX_L4TUNT_UDP 0x1
#define NSE_TXD_CTX_L4TUNT_GRE 0x2
#define NSE_TXD_CTX_L4TUNT_RSV 0x3

	/* rsv: 11 - 1b */

#define NSE_TXD_CTX_L4TUNLEN_S 12
#define NSE_TXD_CTX_L4TUNLEN_M NSE_M(0x7F, 12)

#define NSE_TXD_CTX_L4TUNLEN_MAX_IN_WORD 0x7F
#define NSE_TXD_CTX_L4TUNLEN_MAX_IN_BYTE 0xFE

#define NSE_TXD_CTX_DECTTL_S 19
#define NSE_TXD_CTX_DECTTL_M NSE_M(0xF, 19)

#define NSE_TXD_CTX_L4T_CS_S 23
#define NSE_TXD_CTX_L4T_CS_M BIT(23)

	/* rsv: 31:24 - 8 b */

	__le16 l2tag2;

	__le16 control;
#define NSE_TXD_CTX_TSEC_S 0
#define NSE_TXD_CTX_TSEC_M BIT(0)

#define NSE_TXD_CTX_PORTID_S 1
#define NSE_TXD_CTX_PORTID_M NSE_M(0x3, 1)

	/* rsv: 51 - 1 b */

#define NSE_TXD_CTX_CRCP_S 4
#define NSE_TXD_CTX_CRCP_M BIT(4)

#define NSE_TXD_CTX_TLS_S 5
#define NSE_TXD_CTX_TLS_M BIT(5)

#define NSE_TXD_CTX_TX_MD_S 6
#define NSE_TXD_CTX_TX_MD_M NSE_M(0xF, 6)

#define NSE_TXD_CTX_TSYN_REG_S 10
#define NSE_TXD_CTX_TSYN_REG_M NSE_M(0x3F, 10)

	__le64 qw1;
	/* for style unified clearness, intentionally not use GENMASK_ULL */

#define NSE_TXD_CTX_DTYPE_S 1
#define NSE_TXD_CTX_DTYPE_M BIT_ULL(1)

#define NSE_TXQ_CTX_PORT_VLD_S 2
#define NSE_TXQ_CTX_PORT_VLD_M BIT_ULL(2)

#define NSE_TXQ_CTX_PORT_LOCK_S 3
#define NSE_TXQ_CTX_PORT_LOCK_M BIT_ULL(3)

#define NSE_TXD_CTX_TSO_S 4
#define NSE_TXD_CTX_TSO_M BIT_ULL(4)

#define NSE_TXD_CTX_TSYN_S 5
#define NSE_TXD_CTX_TSYN_M BIT_ULL(5)

#define NSE_TXD_CTX_IL2TAG2_S 6
#define NSE_TXD_CTX_IL2TAG2_M BIT_ULL(6)

#define NSE_TXD_CTX_IL2TAG_IL2H_S 7
#define NSE_TXD_CTX_IL2TAG_IL2H_M BIT_ULL(7)

#define NSE_TXD_CTX_SWITCH_S 8
#define NSE_TXD_CTX_SWITCH_M (0x3ULL << 8)

#define NSE_TXD_CTX_SWITCH_NONE 0x0ULL
#define NSE_TXD_CTX_SWITCH_UPLINK 0x1ULL
#define NSE_TXD_CTX_SWITCH_LOCAL 0x2ULL
#define NSE_TXD_CTX_SWITCH_VSI 0x3ULL

#define NSE_TXD_CTX_DEST_QUEUE_VLD_S 10
#define NSE_TXD_CTX_DEST_QUEUE_VLD_M BIT_ULL(10)

#define NSE_TXD_CTX_DEST_QUEUE_S 11
#define NSE_TXD_CTX_DEST_QUEUE_M (0x3FFULL << 11)

#define NSE_TXD_CTX_DEST_VSI_S 21
#define NSE_TXD_CTX_DEST_VSI_M (0xFFULL << 21)

	/* rsv: 93 - 1 b */

#define NSE_TXD_CTX_L2TAG1_S 30
#define NSE_TXD_CTX_L2TAG1_M (0xFFFFULL << 30)

#define NSE_TXD_CTX_IL2TAG1_S 46
#define NSE_TXD_CTX_IL2TAG1_M BIT_ULL(46)

	/* rsv: 113:111 - 3 b */

#define NSE_TXD_CTX_MSS_S 50
#define NSE_TXD_CTX_MSS_M (0x3FFFULL << 50)

#define NSE_TXD_CTX_MSS_MIN 88
#define NSE_TXD_CTX_MSS_MAX 8088

} __packed;

/* !!!NOTE: MUST use with NSE_TXD_DTYPE_S or NSE_TXD_CTX_DTYPE_S */
enum nse_tx_desc_dtype_value {
	NSE_TX_DESC_DTYPE_DATA = 0x0ULL,
	NSE_TX_DESC_DTYPE_CTX = 0x1ULL,
};

/* Tx CompletionQ Descriptor */
struct nse_lan_txcq_desc {
	__le32 data;

#define NSE_LAN_TXCQD_TXQ_ID_S 0
#define NSE_LAN_TXCQD_TXQ_ID_M NSE_M(0x3FF, 0)

	/* rsv: 10 ~ 13: 4 b */

	/* rsv: 14: 1 b */

#define NSE_LAN_TXCQD_GENERATION_S 15
#define NSE_LAN_TXCQD_GENERATION_M BIT(15)

#define NSE_LAN_TXCQD_TX_HEAD_S 16
#define NSE_LAN_TXCQD_TX_HEAD_M NSE_M(0x1FFF, 16)

#define NSE_LAN_TXCQD_COMPLETION_TYPE_S 29
#define NSE_LAN_TXCQD_COMPLETION_TYPE_M NSE_M(0x7, 29)

#define NSE_LAN_TXCQD_COMPLETION_TYPE_ITR 0x0
#define NSE_LAN_TXCQD_COMPLETION_TYPE_RS 0x1

} __packed;

struct nsevf_vsi_hw_stats {
	u64 rx_drop_err;
	u64 rx_drop_no_desc;
	u64 rx_dpkt;
	u64 rx_goct;
	u64 rx_gpkt;
	u64 rx_mpkt;
	u64 rx_bpkt;

	/* the following are caculated */
	u64 rx_upkt;

	u64 tx_gptc;
	u64 tx_gotc;
	u64 tx_dptc;
	u64 tx_mptc;
	u64 tx_bptc;

	/* the following are caculated */
	u64 tx_uptc;
};

struct nsevf_vsi_sw_stats {
	u64 rx_pkts;
	u64 rx_bytes;
	u64 tx_pkts;
	u64 tx_bytes;

	u64 tx_linearize;
	u64 tx_restart;
	u64 tx_busy;

	u64 rx_csum_good;
	u64 rx_csum_bad;

	u64 fdir_match;
	u64 fdir_miss;

	u64 rx_buf_failed;
	u64 rx_page_failed;
	u64 page_reuse_count;
};

struct nse_dim {
	u32 itr;
};

#define NSE_DIM_DEFAULT_PROFILE_IX 0

#define NSEVF_SR_PBA_FLAGS 0x15
#define NSEVF_SR_PBA_BLOCK_PTR 0x16
#define NSEVF_SR_BOOT_CONFIG_PTR 0x17
#define NSEVF_SR_PERMANENT_SAN_MAC_ADDRESS_PTR 0x28
#define NSEVF_SR_NVM_MAP_VERSION 0x29
#define NSEVF_SR_NVM_IMAGE_VERSION 0x2A
#define NSEVF_SR_NVM_STRUCTURE_VERSION 0x2B
#define NSEVF_SR_OCP_CFG_WORD0 0x2B
#define NSEVF_SR_OCP_ENABLED BIT(15)

struct nsevf_lldp_variables {
	u16 length;
	u16 adminstatus;
	u16 msgfasttx;
	u16 msgtxinterval;
	u16 txparams;
	u16 timers;
	u16 crc8;
};

/* Offsets into Alternate Ram */
#define NSEVF_ALT_STRUCT_FIRST_PF_OFFSET 0 /* in dwords */
#define NSEVF_ALT_STRUCT_DWORDS_PER_PF 64 /* in dwords */
#define NSEVF_ALT_STRUCT_OUTER_VLAN_TAG_OFFSET 0xD /* in dwords */
#define NSEVF_ALT_STRUCT_USER_PRIORITY_OFFSET 0xC /* in dwords */
#define NSEVF_ALT_STRUCT_MIN_BW_OFFSET 0xE /* in dwords */
#define NSEVF_ALT_STRUCT_MAX_BW_OFFSET 0xF /* in dwords */

/* Alternate Ram Bandwidth Masks */
#define NSEVF_ALT_BW_VALUE_MASK 0xFF
#define NSEVF_ALT_BW_RELATIVE_MASK 0x40000000
#define NSEVF_ALT_BW_VALID_MASK 0x80000000

#define NSEVF_DDP_TRACKID_RDONLY 0
#define NSEVF_DDP_TRACKID_INVALID 0xFFFFFFFF
#define SECTION_TYPE_RB_MMIO 0x00001800
#define SECTION_TYPE_RB_AQ 0x00001801
#define SECTION_TYPE_PROTO 0x80000002
#define SECTION_TYPE_PCTYPE 0x80000003
#define SECTION_TYPE_PTYPE 0x80000004
struct nsevf_profile_tlv_section_record {
	u8 rtype;
	u8 type;
	u16 len;
	u8 data[12];
};

/* Generic AQ section in proflie */
struct nsevf_profile_aq_section {
	u16 opcode;
	u16 flags;
	u8 param[16];
	u16 datalen;
	/* Preserve the size and layout of the legacy one-element structure. */
	union {
		u8 data_legacy;
		DECLARE_FLEX_ARRAY(u8, data);
	};
};

struct nse_rx_ptype_decoded {
	u32 known : 1;
	u32 outer_ip : 1;
	u32 outer_ip_ver : 2;
	u32 outer_frag : 1;
	u32 tunnel_type : 3;
	u32 tunnel_end_prot : 2;
	u32 tunnel_end_frag : 1;
	u32 inner_prot : 4;
	u32 payload_layer : 3;
};

enum nse_rx_ptype_outer_ip {
	NSE_RX_PTYPE_OUTER_L2 = 0,
	NSE_RX_PTYPE_OUTER_IP = 1,
};

enum nse_rx_ptype_outer_ip_ver {
	NSE_RX_PTYPE_OUTER_NONE = 0,
	NSE_RX_PTYPE_OUTER_IPV4 = 1,
	NSE_RX_PTYPE_OUTER_IPV6 = 2,
};

enum nse_rx_ptype_outer_fragmented {
	NSE_RX_PTYPE_NOT_FRAG = 0,
	NSE_RX_PTYPE_FRAG = 1,
};

enum nse_rx_ptype_tunnel_type {
	NSE_RX_PTYPE_TUNNEL_NONE = 0,
	NSE_RX_PTYPE_TUNNEL_IP_IP = 1,
	NSE_RX_PTYPE_TUNNEL_IP_GRENAT = 2,
	NSE_RX_PTYPE_TUNNEL_IP_GRENAT_MAC = 3,
	NSE_RX_PTYPE_TUNNEL_IP_GRENAT_MAC_VLAN = 4,
};

enum nse_rx_ptype_tunnel_end_prot {
	NSE_RX_PTYPE_TUNNEL_END_NONE = 0,
	NSE_RX_PTYPE_TUNNEL_END_IPV4 = 1,
	NSE_RX_PTYPE_TUNNEL_END_IPV6 = 2,
};

enum nse_rx_ptype_inner_prot {
	NSE_RX_PTYPE_INNER_PROT_NONE = 0,
	NSE_RX_PTYPE_INNER_PROT_UDP = 1,
	NSE_RX_PTYPE_INNER_PROT_TCP = 2,
	NSE_RX_PTYPE_INNER_PROT_SCTP = 3,
	NSE_RX_PTYPE_INNER_PROT_ICMP = 4,
	NSE_RX_PTYPE_INNER_PROT_TIMESYNC = 5,
};

enum nse_rx_ptype_payload_layer {
	NSE_RX_PTYPE_PAYLOAD_LAYER_NONE = 0,
	NSE_RX_PTYPE_PAYLOAD_LAYER_PAY2 = 1,
	NSE_RX_PTYPE_PAYLOAD_LAYER_PAY3 = 2,
	NSE_RX_PTYPE_PAYLOAD_LAYER_PAY4 = 3,
};

/* The nse_ptype_lkup table is used to convert from the 9-bit ptype in the
 * hardware to a bit-field that can be used by SW to more easily determine the
 * packet type.
 *
 * Macros are used to shorten the table lines and make this table human
 * readable.
 *
 * We store the PTYPE in the top byte of the bit field - this is just so that
 * we can check that the table doesn't have a row missing, as the index into
 * the table should be the PTYPE.
 *
 * Typical work flow:
 *
 * IF NOT nse_ptype_lkup[ptype].known
 * THEN
 *      Packet is unknown
 * ELSE IF nse_ptype_lkup[ptype].outer_ip == NSE_RX_PTYPE_OUTER_IP
 *      Use the rest of the fields to look at the tunnels, inner protocols, etc
 * ELSE
 *      Use the enum nse_rx_l2_ptype to decode the packet type
 * ENDIF
 */

/* macro to make the table lines short, use explicit indexing with [PTYPE] */
#define NSE_PTT(PTYPE, OUTER_IP, OUTER_IP_VER, OUTER_FRAG, T, TE, TEF, I, PL) \
	[PTYPE] = { 1,                                                        \
		    NSE_RX_PTYPE_OUTER_##OUTER_IP,                            \
		    NSE_RX_PTYPE_OUTER_##OUTER_IP_VER,                        \
		    NSE_RX_PTYPE_##OUTER_FRAG,                                \
		    NSE_RX_PTYPE_TUNNEL_##T,                                  \
		    NSE_RX_PTYPE_TUNNEL_END_##TE,                             \
		    NSE_RX_PTYPE_##TEF,                                       \
		    NSE_RX_PTYPE_INNER_PROT_##I,                              \
		    NSE_RX_PTYPE_PAYLOAD_LAYER_##PL }

#define NSE_PTT_UNUSED_ENTRY(PTYPE) \
	[PTYPE] = { 0, 0, 0, 0, 0, 0, 0, 0, 0 }

/* shorter macros makes the table fit but are terse */
#define NSE_RX_PTYPE_NOF NSE_RX_PTYPE_NOT_FRAG
#define NSE_RX_PTYPE_FRG NSE_RX_PTYPE_FRAG
#define NSE_RX_PTYPE_INNER_PROT_TS NSE_RX_PTYPE_INNER_PROT_TIMESYNC

extern const struct nse_rx_ptype_decoded nse_ptype_lkup[256];

static inline struct nse_rx_ptype_decoded nse_decode_rx_desc_ptype(u8 ptype)
{
	return nse_ptype_lkup[ptype];
}

#endif /* _NSEVF_TYPE_H_ */
