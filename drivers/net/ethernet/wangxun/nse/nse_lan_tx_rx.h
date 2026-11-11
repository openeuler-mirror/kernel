/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_LAN_TX_RX_H_
#define _NSE_LAN_TX_RX_H_
#include "nse_osdep.h"

#define NSE_LAN_TXQ_MAX_QGRPS	127
#define NSE_LAN_TXQ_MAX_QDIS	1023

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

		/* Q_src: 2 b, Src_port: 2 b, Md0_vld: 1 b, Md1_vld: 1 b, rsv: 2b */
		u8 qsrc_sport_md01valid;
#define NSE_RXD_QSRC_S			0
#define NSE_RXD_QSRC_M			NSE_M(0x3, 0)

	#define NSE_RXD_QSRC_SW		0x0
	#define NSE_RXD_QSRC_ACL	0x1
	#define NSE_RXD_QSRC_FD		0x2
	#define NSE_RXD_QSRC_RSS	0x3

#define NSE_RXD_SPORT_S			2
#define NSE_RXD_SPORT_M			NSE_M(0x3, 2)

	#define NSE_RXD_SPORT_LAN		0x0
	#define NSE_RXD_SPORT_LOOPBACK	0x1
	#define NSE_RXD_SPORT_BMC		0x2
	#define NSE_RXD_SPORT_MNG		0x3

#define NSE_RXD_MD0_VALID_S		4
#define NSE_RXD_MD0_VALID_M		BIT(4)

#define NSE_RXD_MD1_VALID_S		5
#define NSE_RXD_MD1_VALID_M		BIT(5)

		/* Word 1 */
		__le16 l2tag1_nextp;	/* L2TAG1: 16 b, OR: NEXTP: 16 b*/

		/* Word 2 */
		__le16 md0;		/* FlexiMD.0: 16 b*/

		/* Word 3 */
		__le16 md1;		/* FlexiMD.1: 16 b*/

		/* Word 4 */
		__le16 status_error0;
#define NSE_RXD_STATUS0_DD_S			0
#define NSE_RXD_STATUS0_DD_M			BIT(0)

#define NSE_RXD_STATUS0_EOP_S			1
#define NSE_RXD_STATUS0_EOP_M			BIT(1)

#define NSE_RXD_STATUS0_HBO_S			2
#define NSE_RXD_STATUS0_HBO_M			BIT(2)

#define NSE_RXD_STATUS0_EIPV6EX_S		3
#define NSE_RXD_STATUS0_EIPV6EX_M		BIT(3)

#define NSE_RXD_STATUS0_XSUM_IPE_S		4
#define NSE_RXD_STATUS0_XSUM_IPE_M		BIT(4)

#define NSE_RXD_STATUS0_XSUM_L4E_S		5
#define NSE_RXD_STATUS0_XSUM_L4E_M		BIT(5)

#define NSE_RXD_STATUS0_XSUM_EIPE_S		6
#define NSE_RXD_STATUS0_XSUM_EIPE_M		BIT(6)

#define NSE_RXD_STATUS0_XSUM_EUDPE_S	7
#define NSE_RXD_STATUS0_XSUM_EUDPE_M	BIT(7)

#define NSE_RXD_STATUS0_MIRR_S			8
#define NSE_RXD_STATUS0_MIRR_M			BIT(8)

#define NSE_RXD_STATUS0_IPV6EXADD_S		9
#define NSE_RXD_STATUS0_IPV6EXADD_M		BIT(9)

#define NSE_RXD_STATUS0_RXE_S			10
#define NSE_RXD_STATUS0_RXE_M			BIT(10)

#define NSE_RXD_STATUS0_CRCP_S			11
#define NSE_RXD_STATUS0_CRCP_M			BIT(11)

#define NSE_RXD_STATUS0_PTP_S			12
#define NSE_RXD_STATUS0_PTP_M			BIT(12)

#define NSE_RXD_STATUS0_L2TAG1P_S		13
#define NSE_RXD_STATUS0_L2TAG1P_M		BIT(13)

#define NSE_RXD_STATUS0_EXT_UDP_0_S		14
#define NSE_RXD_STATUS0_EXT_UDP_0_M		BIT(14)

#define NSE_RXD_STATUS0_INT_UDP_0_S		15
#define NSE_RXD_STATUS0_INT_UDP_0_M		BIT(15)

		/* Word 5 */
		u8 ptype;		/* PTYPE: 8 b */

		/* rsv: 1b, Fdir_err: 3 b, lksec: 1 b, secerr: 2b, sni: 1b */
		u8 misc;
#define NSE_RXD_FDIR_ERR_S	1
#define NSE_RXD_FDIR_ERR_M	NSE_M(0x7, 1)

#define NSE_RXD_LKSEC_S		4
#define NSE_RXD_LKSEC_M		BIT(4)

#define NSE_RXD_SECERR_S	5
#define NSE_RXD_SECERR_M	NSE_M(0x3, 5)

	#define NSE_RXD_SECERR_NO_ERROR			0x0
	#define NSE_RXD_SECERR_NO_SA			0x1
	#define NSE_RXD_SECERR_REPLAY_ERROR		0x2
	#define NSE_RXD_SECERR_ICV_ERROR		0x3

#define NSE_RXD_SNI_S		7
#define NSE_RXD_SNI_M		BIT(7)

		/* Word 6 */
		__le16 pktlen_sph_reentry;	/* Packet Length: 14 b, SPH: 1 b, reentry: 1b */
#define NSE_RXD_PKT_LEN_S	0
#define NSE_RXD_PKT_LEN_M	0x3FFF

#define NSE_RXD_SPH_S		14
#define NSE_RXD_SPH_M		BIT(14)

#define NSE_RXD_REENTRY_S	15
#define NSE_RXD_REENTRY_M	BIT(15)

		/* Word 7 */
		__le16 hdrlen_rsccnt;		/* Header Length: 10 b, Rsccnt: 4 b, rsv: 2b */
#define NSE_RXD_HDR_LEN_S	0
#define NSE_RXD_HDR_LEN_M	0x3FF

#define NSE_RXD_RSCCNT_S	10
#define NSE_RXD_RSCCNT_M	NSE_M(0xF, 10)

		/* Word 8 */
		u8 status_error1;	/* Status/Error.1: 8 b */
#define NSE_RXD_STATUS1_V6M_S			0
#define NSE_RXD_STATUS1_V6M_M			BIT(0)

#define NSE_RXD_STATUS1_TLS_S			1
#define NSE_RXD_STATUS1_TLS_M			BIT(1)

#define NSE_RXD_STATUS1_L2TAG2P_S		2
#define NSE_RXD_STATUS1_L2TAG2P_M		BIT(2)

#define NSE_RXD_STATUS1_MD2_VALID_S		3
#define NSE_RXD_STATUS1_MD2_VALID_M		BIT(3)

#define NSE_RXD_STATUS1_MD3_VALID_S		4
#define NSE_RXD_STATUS1_MD3_VALID_M		BIT(4)

#define NSE_RXD_STATUS1_MD4_VALID_S		5
#define NSE_RXD_STATUS1_MD4_VALID_M		BIT(5)

#define NSE_RXD_STATUS1_MD5_VALID_S		6
#define NSE_RXD_STATUS1_MD5_VALID_M		BIT(6)

#define NSE_RXD_STATUS1_MD6_VALID_S		7
#define NSE_RXD_STATUS1_MD6_VALID_M		BIT(7)

		u8 ts_low;			/* TS.L: 8 b */

		/* Word 9 */
		__le16 md6;			/* FlexMD.6: 16 b */

		/* Word 10, 11*/
		__le16 l2tag2_1st;	/* L2TAG2 (1st): 16 b */
		__le16 l2tag2_2nd;	/* L2TAG2 (2nd): 16 b */

		/* Word 12, 13 */
		__le16 md2;			/* FlexiMD.2: 16 b */
		__le16 md3;			/* FlexiMD.3: 16 b*/

		/* Word 14, 15 */
		union {
			struct {
				__le16 md4;	/* FlexiMD.4: 16 b */
				__le16 md5;	/* FlexiMD.5: 16 b */
			} __packed;
			__le32 ts_high;
		};
	} wb; /* writeback */

} __packed;

enum nse_rxdid {
	NSE_RXDID_FLEX_BLANK		= 0,
	NSE_RXDID_FLEX_NIC			= 1,
	NSE_RXDID_FLEX_SWITCHDEV	= 2,

#if defined(NSE_DEBUG_EXT)
	NSE_RXDID_FLEX_DBG_0		= 15,	/* for various debug */
#endif

	NSE_RXDID_MAX			= 16,
};

#define NSE_RXD_FLEXI_MD6_SFLOW_VALID_S		11
#define NSE_RXD_FLEXI_MD6_SFLOW_VALID_M		BIT(NSE_RXD_FLEXI_MD6_SFLOW_VALID_S)

#define NSE_RXD_FLEXI_MD6_CHAIN_ID_S		8 /*bit 10:8*/
#define NSE_RXD_FLEXI_MD6_CHAIN_ID_M		0x7

/* Rx Flex Descriptor NIC Profile
 * RxDID Profile: NSE_RXDID_FLEX_NIC
 * FlexiMD.0: RSS hash lower 16-bits from POH-MDID
 * FlexiMD.1: RSS hash upper 16-bits from POH-MDID
 * FlexiMD.2: FDir fdir_hash_result 16-bits from POH-MDID
 * FlexiMD.3: FDir fdir_filter_id 16-bits from POH-MDID
 * FlexiMD.4: unused or ts_high word #0
 * FlexiMD.5: unused or ts_high word #1
 * FlexiMD.6: Source VSI/LAN from POH-MDID
 */
struct nse_32b_rx_desc_nic {
	/* Word 0 */
	u8 rxdid; /* RXDID: 4 b rsv: 4 b */
	/* Q_src: 2 b, Src_port: 2 b, Md0_vld: 1 b, Md1_vld: 1 b, rsv: 2b */
	u8 qsrc_sport_md01valid;
	/* Word 1 */
	__le16 l2tag1_nextp;	/* L2TAG1: 16 b, OR: NEXTP: 16 b*/

	/* Word 2 - FlexMD.0: RSS hash lower 16-bits from POH-MDID
	 *
	 * Word 3 - FlexMD.1: RSS hash upper 16-bits from POH-MDID
	 **/
	__le32 rss_hash;

	/* Word 4 */
	__le16 status_error0;
	/* Word 5 */
	u8 ptype;		/* PTYPE: 8 b */
	u8 misc;		/* rsv: 1b, Fdir_err: 3 b, lksec: 1 b, secerr: 2b, sni: 1b */
	/* Word 6 */
	__le16 pktlen_sph_reentry;	/* Packet Length: 14 b, SPH: 1 b, reentry: 1b */
	/* Word 7 */
	__le16 hdrlen_rsccnt;		/* Header Length: 10 b, Rsccnt: 4 b */
	/* Word 8 */
	u8 status_error1;	/* Status/Error.1: 8 b */
	u8 ts_low;			/* TS.L: 8 b */

	__le16 source_vsi_lan;

	/* Word 10, 11*/
	__le16 l2tag2_1st;	/* L2TAG2 (1st): 16 b */
	__le16 l2tag2_2nd;	/* L2TAG2 (2nd): 16 b */

	/* Word 12 - FlexiMD.2: FDir fdir_hash_result 16-bits from POH-MDID
	 *
	 * Word 13 - FlexiMD.3: FDir fdir_filter_id 16-bits from POH-MDID
	 **/
	__le16 fdir_hash_result;
	__le16 fdir_filter_id;

	/* Word 14, 15 */
	union {
		struct {
			__le16 md4;	/* FlexiMD.4: 16 b */
			__le16 md5;	/* FlexiMD.5: 16 b */
		} __packed;
		__le32 ts_high;
	};

} __packed;

/* Rx Flex Descriptor NIC Profile
 * RxDID Profile: NSE_RXDID_FLEX_SWITCHDEV
 * FlexiMD.0: RSS hash lower 16-bits from POH-MDID
 * FlexiMD.1: RSS hash upper 16-bits from POH-MDID
 * FlexiMD.2: FDir fdir_hash_result 16-bits from POH-MDID
 * FlexiMD.3: FDir fdir_filter_id 16-bits from POH-MDID
 * FlexiMD.4: unused or ts_high word #0
 * FlexiMD.5: unused or ts_high word #1
 * FlexiMD.6: Source VSI/LAN from POH-MDID
 */
struct nse_32b_rx_desc_switchdev {
	/* Word 0 */
	u8 rxdid; /* RXDID: 4 b rsv: 4 b */
	/* Q_src: 2 b, Src_port: 2 b, Md0_vld: 1 b, Md1_vld: 1 b, rsv: 2b */
	u8 qsrc_sport_md01valid;
	/* Word 1 */
	__le16 l2tag1_nextp;	/* L2TAG1: 16 b, OR: NEXTP: 16 b*/

	/* Word 2 - FlexMD.0: RSS hash lower 16-bits from POH-MDID
	 *
	 * Word 3 - FlexMD.1: RSS hash upper 16-bits from POH-MDID
	 **/
	__le32 rss_hash;

	/* Word 4 */
	__le16 status_error0;
	/* Word 5 */
	u8 ptype;		/* PTYPE: 8 b */
	u8 misc;		/* rsv: 1b, Fdir_err: 3 b, lksec: 1 b, secerr: 2b, sni: 1b */
	/* Word 6 */
	__le16 pktlen_sph_reentry;	/* Packet Length: 14 b, SPH: 1 b, reentry: 1b */
	/* Word 7 */
	__le16 hdrlen_rsccnt;		/* Header Length: 10 b, Rsccnt: 4 b */
	/* Word 8 */
	u8 status_error1;	/* Status/Error.1: 8 b */
	u8 ts_low;			/* TS.L: 8 b */

	__le16 source_vsi_lan;

	/* Word 10, 11*/
	__le16 l2tag2_1st;	/* L2TAG2 (1st): 16 b */
	__le16 l2tag2_2nd;	/* L2TAG2 (2nd): 16 b */

	/* Word 12 - FlexiMD.2: FDir fdir_hash_result 16-bits from POH-MDID
	 *
	 * Word 13 - FlexiMD.3: FDir fdir_filter_id 16-bits from POH-MDID
	 **/
	__le16 fdir_hash_result;
	__le16 fdir_filter_id;

	/* Word 14, 15 */
	union {
		struct {
			__le16 md4;	/* FlexiMD.4: 16 b */
			__le16 md5;	/* FlexiMD.5: 16 b */
		} __packed;
		__le32 ts_high;
	};

} __packed;

#if defined(NSE_DEBUG_EXT)
/* Rx Flex Descriptor Profile: DBG_0
 * RxDID Profile: NSE_RXDID_FLEX_DBG_0
 *
 *		Note, when doing debug, need FW to modify its RXDID profile configuration code,
 *		to fill RXDID=NSE_RXDID_FLEX_DBG_0(15) entry
 *
 *		Otherwise, can not debug.
 *
 *
 * FlexiMD.0: to debug RSC.
 *				POH_MD[37] - in RDM, it is set to be: POH_MD[37] = poh[223:208],
 *
 *					poh[219] 'rscfv'	-	bit 11 in FlexiMD.0
 *
 * FlexiMD.1: unused
 * FlexiMD.2: unused
 * FlexiMD.3: unused
 * FlexiMD.4: unused or ts_high word #0
 * FlexiMD.5: unused or ts_high word #1
 * FlexiMD.6: unused
 */
struct nse_32b_rx_desc_dbg_0 {
	/* Word 0 */
	u8 rxdid; /* RXDID: 4 b rsv: 4 b */
	/* Q_src: 2 b, Src_port: 2 b, Md0_vld: 1 b, Md1_vld: 1 b, rsv: 2b */
	u8 qsrc_sport_md01valid;

	/* Word 1 */
	__le16 l2tag1_nextp;	/* L2TAG1: 16 b, OR: NEXTP: 16 b*/

	/* Word 2 */
	__le16 poh_md_37;	/* FlexiMD.0: 16 b -- as POH_MD[37]*/

	/* Word 3 */
	__le16 md1;		/* FlexiMD.1: 16 b*/

	/* Word 4 */
	__le16 status_error0;

	/* Word 5 */
	u8 ptype;		/* PTYPE: 8 b */
	u8 misc;		/* rsv: 1b, Fdir_err: 3 b, lksec: 1 b, secerr: 2b, sni: 1b */

	/* Word 6 */
	__le16 pktlen_sph_reentry;	/* Packet Length: 14 b, SPH: 1 b, reentry: 1b */

	/* Word 7 */
	__le16 hdrlen_rsccnt;		/* Header Length: 10 b, Rsccnt: 4 b */

	/* Word 8 */
	u8 status_error1;	/* Status/Error.1: 8 b */
	u8 ts_low;			/* TS.L: 8 b */

	/* Word 9 */
	__le16 md6;			/* FlexMD.6: 16 b */

	/* Word 10, 11*/
	__le16 l2tag2_1st;	/* L2TAG2 (1st): 16 b */
	__le16 l2tag2_2nd;	/* L2TAG2 (2nd): 16 b */

	/* Word 12, 13 */
	__le16 md2;			/* FlexiMD.2: 16 b */
	__le16 md3;			/* FlexiMD.3: 16 b*/

	/* Word 14, 15 */
	union {
		struct {
			__le16 md4;	/* FlexiMD.4: 16 b */
			__le16 md5;	/* FlexiMD.5: 16 b */
		} __packed;
		__le32 ts_high;
	};

} __packed;

#endif	/* #if defined(NSE_DEBUG_EXT) */

/* match <nse_adminq_cmd.h> __le32 ctx_data[32] */
#define NSE_LAN_RXQ_CTX_LEN_IN_DWORD_MAX	32

#define NSE_LAN_RXQ_CTX_LEN_IN_DWORD_AMBER	11
#define NSE_LAN_RXQ_CTX_LEN_IN_DWORD_MS		11

struct nse_lan_rxq_ctx_amber {
	u32 data[NSE_LAN_RXQ_CTX_LEN_IN_DWORD_AMBER];

	/* DATA[0]: BASE_low */
/* BASE is in 16-byte units, to fit virtio requirement, not 128-byte unit */
#define AMBER_LAN_RXQ_BASE_SHIFT			4
#define AMBER_LAN_RXQ_CTX_BASE_LOW_S			0
#define AMBER_LAN_RXQ_CTX_BASE_LOW_M			NSE_M(0xFFFFFFFF, 0)

	/* DATA[1]: BASE_high, TPHRDesc, TPHWDesc, Desc_coalesc_en, Cause_en */
#define AMBER_LAN_RXQ_CTX_BASE_HIGH_S		0
#define AMBER_LAN_RXQ_CTX_BASE_HIGH_M		NSE_M(0xFFFFFFF, 0)

#define AMBER_LAN_RXQ_CTX_TPHRDESC_S			28
#define AMBER_LAN_RXQ_CTX_TPHRDESC_M			BIT(28)

#define AMBER_LAN_RXQ_CTX_TPHWDESC_S			29
#define AMBER_LAN_RXQ_CTX_TPHWDESC_M			BIT(29)

#define AMBER_LAN_RXQ_CTX_DESC_COALESC_EN_S	30
#define AMBER_LAN_RXQ_CTX_DESC_COALESC_EN_M	BIT(30)

#define AMBER_LAN_RXQ_CTX_CAUSE_EN_S			31
#define AMBER_LAN_RXQ_CTX_CAUSE_EN_M			BIT(31)

	/* DATA[2]: Msix_idx, DBUFF, HBUFF, CPUID, TS */
#define AMBER_LAN_RXQ_CTX_MSIX_IDX_S			0
#define AMBER_LAN_RXQ_CTX_MSIX_IDX_M			NSE_M(0x3FF, 0)

#define AMBER_LAN_RXQ_CTX_DBUFF_SHIFT		7		/* in 128-byte units */
#define AMBER_LAN_RXQ_CTX_DBUFF_S			10
#define AMBER_LAN_RXQ_CTX_DBUFF_M			NSE_M(0x7F, 10)

#define AMBER_LAN_RXQ_CTX_HBUFF_SHIFT		6		/* in 64-byte units */
#define AMBER_LAN_RXQ_CTX_HBUFF_S			17
#define AMBER_LAN_RXQ_CTX_HBUFF_M			NSE_M(0x1F, 21)

#define AMBER_LAN_RXQ_CTX_CPUID_S			22
#define AMBER_LAN_RXQ_CTX_CPUID_M			NSE_M(0xFF, 22)

#define AMBER_LAN_RXQ_CTX_TS_S				30
#define AMBER_LAN_RXQ_CTX_TS_M				BIT(30)

#define AMBER_LAN_RXQ_CTX_QLEN_S				0
#define AMBER_LAN_RXQ_CTX_QLEN_M				NSE_M(0x1FFF, 0)

#define AMBER_LAN_RXQ_CTX_RSC_EN_S			13
#define AMBER_LAN_RXQ_CTX_RSC_EN_M			BIT(13)

#define AMBER_LAN_RXQ_CTX_RSC_MAX_BUF_S		14
#define AMBER_LAN_RXQ_CTX_RSC_MAX_BUF_M		NSE_M(0x3, 14)

	#define AMBER_LAN_RXQ_CTX_RSC_MAX_BUF_1_BUF		0x0
	#define AMBER_LAN_RXQ_CTX_RSC_MAX_BUF_4_BUF		0x1
	#define AMBER_LAN_RXQ_CTX_RSC_MAX_BUF_8_BUF		0x2
	#define AMBER_LAN_RXQ_CTX_RSC_MAX_BUF_16_BUF		0x3

#define AMBER_LAN_RXQ_CTX_RSC_OVERFLOW_S		16
#define AMBER_LAN_RXQ_CTX_RSC_OVERFLOW_M		BIT(16)

#define AMBER_LAN_RXQ_CTX_DTYPE_S			17
#define AMBER_LAN_RXQ_CTX_DTYPE_M			BIT(17)

	#define AMBER_LAN_RXQ_CTX_DTYPE_SINGLE_BUF_DESC		0x0
	#define AMBER_LAN_RXQ_CTX_DTYPE_HEADER_SPLIT_DESC	0x1

#define AMBER_LAN_RXQ_CTX_DSIZE_S			18
#define AMBER_LAN_RXQ_CTX_DSIZE_M			BIT(18)

	#define AMBER_LAN_RXQ_CTX_DSIZE_16B		0x0
	#define AMBER_LAN_RXQ_CTX_DSIZE_32B		0x1

#define AMBER_LAN_RXQ_CTX_L2TSEL_S			19
#define AMBER_LAN_RXQ_CTX_L2TSEL_M			BIT(19)

#define AMBER_LAN_RXQ_CTX_L2TAG_STRIP_EN_S	20
#define AMBER_LAN_RXQ_CTX_L2TAG_STRIP_EN_M	BIT(20)

#define AMBER_LAN_RXQ_CTX_TPHDATA_S			21
#define AMBER_LAN_RXQ_CTX_TPHDATA_M			BIT(21)

#define AMBER_LAN_RXQ_CTX_TPHHEAD_S			22
#define AMBER_LAN_RXQ_CTX_TPHHEAD_M			BIT(22)

#define AMBER_LAN_RXQ_CTX_LRXQTRESH_S		23
#define AMBER_LAN_RXQ_CTX_LRXQTRESH_M		NSE_M(0x7, 23)

#define AMBER_LAN_RXQ_CTX_LL_S				26
#define AMBER_LAN_RXQ_CTX_LL_M				BIT(26)

#define AMBER_LAN_RXQ_CTX_PF_NUM_S			27
#define AMBER_LAN_RXQ_CTX_PF_NUM_M			NSE_M(0x3, 27)

#define AMBER_LAN_RXQ_CTX_DROP_CTRL_S		29
#define AMBER_LAN_RXQ_CTX_DROP_CTRL_M		NSE_M(0x3, 29)

	#define AMBER_LAN_RXQ_CTX_DROP_CTRL_ALLOW_DROP		0x0
	#define AMBER_LAN_RXQ_CTX_DROP_CTRL_DROP_WAIT		0x1

#define AMBER_LAN_RXQ_CTX_QTYPE_S			31
#define AMBER_LAN_RXQ_CTX_QTYPE_M			BIT(31)

	#define AMBER_LAN_RXQ_CTX_QTYPE_NATIVE		0x0
	#define AMBER_LAN_RXQ_CTX_QTYPE_VIRTIO		0x1

	/* DATA[4]: RXDID, HSPLIT_0, HSPLIT_1, VSI, Statistic_cnt_id, Statistic_en */
#define AMBER_LAN_RXQ_CTX_RXDID_S			0
#define AMBER_LAN_RXQ_CTX_RXDID_M			NSE_M(0xF, 0)

#define AMBER_LAN_RXQ_CTX_HSPLIT0_S			4
#define AMBER_LAN_RXQ_CTX_HSPLIT0_M			NSE_M(0xF, 4)

	#define AMBER_LAN_RXQ_CTX_HSPLIT0_NO_SPLIT			0x0
	#define AMBER_LAN_RXQ_CTX_HSPLIT0_SPLIT_L2			0x1
	#define AMBER_LAN_RXQ_CTX_HSPLIT0_SPLIT_IP			0x2
	#define AMBER_LAN_RXQ_CTX_HSPLIT0_SPLIT_TCP_UDP		0x4

#define AMBER_LAN_RXQ_CTX_HSPLIT1_S			8
#define AMBER_LAN_RXQ_CTX_HSPLIT1_M			NSE_M(0x3, 8)

	#define AMBER_LAN_RXQ_CTX_HSPLIT1_NO_SPLIT			0x0
	#define AMBER_LAN_RXQ_CTX_HSPLIT1_SPLIT_L2			0x1
	#define AMBER_LAN_RXQ_CTX_HSPLIT1_SPLIT_ALWAYS		0x2

#define AMBER_LAN_RXQ_CTX_VSI_S				10
#define AMBER_LAN_RXQ_CTX_VSI_M				NSE_M(0xFF, 10)

#define AMBER_LAN_RXQ_CTX_STATS_CNT_ID_S		18
#define AMBER_LAN_RXQ_CTX_STATS_CNT_ID_M		NSE_M(0xF, 18)

#define AMBER_LAN_RXQ_CTX_STATS_EN_S			22
#define AMBER_LAN_RXQ_CTX_STATS_EN_M			BIT(22)

	/* DATA[5]: vis_addr_l */
	/* DATA[6]: vis_addr_h */
#define AMBER_LAN_RXQ_CTX_VIS_ADDR_L_S		0
#define AMBER_LAN_RXQ_CTX_VIS_ADDR_L_M		NSE_M(0xFFFFFFFF, 0)

#define AMBER_LAN_RXQ_CTX_VIS_ADDR_H_S		0
#define AMBER_LAN_RXQ_CTX_VIS_ADDR_H_M		NSE_M(0xFFFFFFFF, 0)

	/* DATA[7]: TAIL, TAIL_WRAP_CNT, HEAD, HEAD_WRAP_CNT */
#define AMBER_LAN_RXQ_CTX_HEAD_WRAP_CNT_S	31
#define AMBER_LAN_RXQ_CTX_HEAD_WRAP_CNT_M	BIT(31)

#define AMBER_LAN_RXQ_CTX_HEAD_S				16
#define AMBER_LAN_RXQ_CTX_HEAD_M				NSE_M(0x1FFF, 16)

#define AMBER_LAN_RXQ_CTX_TAIL_WRAP_CNT_S	15
#define AMBER_LAN_RXQ_CTX_TAIL_WRAP_CNT_M	BIT(15)

#define AMBER_LAN_RXQ_CTX_TAIL_S				0
#define AMBER_LAN_RXQ_CTX_TAIL_M				NSE_M(0x1FFF, 0)

	/* DATA[8]: fetch, fetch_wrap_cnt, pre_used, pre_used_wrap_cnt */
#define AMBER_LAN_RXQ_CTX_PRE_USED_WRAP_CNT_S	29
#define AMBER_LAN_RXQ_CTX_PRE_USED_WRAP_CNT_M	BIT(29)

#define AMBER_LAN_RXQ_CTX_PRE_USED_S				16
#define AMBER_LAN_RXQ_CTX_PRE_USED_M				NSE_M(0x1FFF, 16)

#define AMBER_LAN_RXQ_CTX_FETCH_WRAP_CNT_S		13
#define AMBER_LAN_RXQ_CTX_FETCH_WRAP_CNT_M		BIT(13)

#define AMBER_LAN_RXQ_CTX_FETCH_S				0
#define AMBER_LAN_RXQ_CTX_FETCH_M				NSE_M(0x1FFF, 0)

	/* DATA[9]: qmrd_cnt, real_cnt */
#define AMBER_LAN_RXQ_CTX_QMRD_CNT_S				16
#define AMBER_LAN_RXQ_CTX_QMRD_CNT_M				NSE_M(0xFF, 16)

#define AMBER_LAN_RXQ_CTX_REAL_CNT_S				0
#define AMBER_LAN_RXQ_CTX_REAL_CNT_M				NSE_M(0x1FFF, 0)

	/* DATA[10]: virtio_desc_len, est_cnt */
#define AMBER_LAN_RXQ_CTX_VIRTIO_DESC_LEN_S		16
#define AMBER_LAN_RXQ_CTX_VIRTIO_DESC_LEN_M		NSE_M(0x3FFF, 16)

#define AMBER_LAN_RXQ_CTX_EST_CNT_S				0
#define AMBER_LAN_RXQ_CTX_EST_CNT_M				NSE_M(0x3FFF, 0)

} __packed;

struct nse_lan_rxq_ctx_ms {
	u32 data[NSE_LAN_RXQ_CTX_LEN_IN_DWORD_MS];

	/* DATA[0] */
/* BASE is in 16-byte units, to fit virtio requirement, not 128-byte unit */
#define MS_LAN_RXQ_BASE_SHIFT			4
#define MS_LAN_RXQ_CTX_BASE_LOW_S			0
#define MS_LAN_RXQ_CTX_BASE_LOW_M			NSE_M(0xFFFFFFFF, 0)

	/* DATA[1] */
#define MS_LAN_RXQ_CTX_CAUSE_EN_S			31
#define MS_LAN_RXQ_CTX_CAUSE_EN_M			BIT(31)

#define MS_LAN_RXQ_CTX_DESC_COALESC_EN_S	30
#define MS_LAN_RXQ_CTX_DESC_COALESC_EN_M	BIT(30)

#define MS_LAN_RXQ_CTX_TPHWDESC_S			29
#define MS_LAN_RXQ_CTX_TPHWDESC_M			BIT(29)

#define MS_LAN_RXQ_CTX_TPHRDESC_S			28
#define MS_LAN_RXQ_CTX_TPHRDESC_M			BIT(28)

#define MS_LAN_RXQ_CTX_BASE_HIGH_S		0
#define MS_LAN_RXQ_CTX_BASE_HIGH_M		NSE_M(0xFFFFFFF, 0)

	/* DATA[2] */
#define MS_LAN_RXQ_CTX_TS_S				30
#define MS_LAN_RXQ_CTX_TS_M				BIT(30)

#define MS_LAN_RXQ_CTX_CPUID_S			22
#define MS_LAN_RXQ_CTX_CPUID_M			NSE_M(0xFF, 22)

#define MS_LAN_RXQ_CTX_DBUFF_SHIFT		7		/* in 128-byte units */
#define MS_LAN_RXQ_CTX_DBUFF_S			10
#define MS_LAN_RXQ_CTX_DBUFF_M			NSE_M(0x7F, 10)

#define MS_LAN_RXQ_CTX_MSIX_IDX_S			0
#define MS_LAN_RXQ_CTX_MSIX_IDX_M			NSE_M(0x3FF, 0)

	/* DATA[3] */
#define MS_LAN_RXQ_CTX_DROP_CTRL_S		29
#define MS_LAN_RXQ_CTX_DROP_CTRL_M		NSE_M(0x3, 29)

	#define MS_LAN_RXQ_CTX_DROP_CTRL_ALLOW_DROP		0x0
	#define MS_LAN_RXQ_CTX_DROP_CTRL_DROP_WAIT		0x1

#define MS_LAN_RXQ_CTX_PF_NUM_S			27
#define MS_LAN_RXQ_CTX_PF_NUM_M			NSE_M(0x3, 27)

#define MS_LAN_RXQ_CTX_LRXQTRESH_S		23
#define MS_LAN_RXQ_CTX_LRXQTRESH_M		NSE_M(0x7, 23)

#define MS_LAN_RXQ_CTX_TPHDATA_S			21
#define MS_LAN_RXQ_CTX_TPHDATA_M			BIT(21)

#define MS_LAN_RXQ_CTX_L2TAG_STRIP_EN_S	20
#define MS_LAN_RXQ_CTX_L2TAG_STRIP_EN_M	BIT(20)

#define MS_LAN_RXQ_CTX_L2TSEL_S			19
#define MS_LAN_RXQ_CTX_L2TSEL_M			BIT(19)

#define MS_LAN_RXQ_CTX_DSIZE_S			18
#define MS_LAN_RXQ_CTX_DSIZE_M			BIT(18)

	#define MS_LAN_RXQ_CTX_DSIZE_16B		0x0
	#define MS_LAN_RXQ_CTX_DSIZE_32B		0x1

#define MS_LAN_RXQ_CTX_QLEN_S				0
#define MS_LAN_RXQ_CTX_QLEN_M				NSE_M(0x1FFF, 0)

	/* DATA[4] */
#define MS_LAN_RXQ_CTX_VSI_S				10
#define MS_LAN_RXQ_CTX_VSI_M				NSE_M(0x7, 10)

	/* DATA[5]: not used in ms */
	/* DATA[6]: not used in ms */

	/* DATA[7] */
#define MS_LAN_RXQ_CTX_HEAD_WRAP_CNT_S	31
#define MS_LAN_RXQ_CTX_HEAD_WRAP_CNT_M	BIT(31)

#define MS_LAN_RXQ_CTX_HEAD_S				16
#define MS_LAN_RXQ_CTX_HEAD_M				NSE_M(0x1FFF, 16)

#define MS_LAN_RXQ_CTX_TAIL_WRAP_CNT_S	15
#define MS_LAN_RXQ_CTX_TAIL_WRAP_CNT_M	BIT(15)

#define MS_LAN_RXQ_CTX_TAIL_S				0
#define MS_LAN_RXQ_CTX_TAIL_M				NSE_M(0x1FFF, 0)

	/* DATA[8] */
#define MS_LAN_RXQ_CTX_PRE_USED_WRAP_CNT_S	29
#define MS_LAN_RXQ_CTX_PRE_USED_WRAP_CNT_M	BIT(29)

#define MS_LAN_RXQ_CTX_PRE_USED_S				16
#define MS_LAN_RXQ_CTX_PRE_USED_M				NSE_M(0x1FFF, 16)

#define MS_LAN_RXQ_CTX_FETCH_WRAP_CNT_S		13
#define MS_LAN_RXQ_CTX_FETCH_WRAP_CNT_M		BIT(13)

#define MS_LAN_RXQ_CTX_FETCH_S				0
#define MS_LAN_RXQ_CTX_FETCH_M				NSE_M(0x1FFF, 0)

	/* DATA[9] */
#define MS_LAN_RXQ_CTX_QMRD_CNT_S				16
#define MS_LAN_RXQ_CTX_QMRD_CNT_M				NSE_M(0xFF, 16)

#define MS_LAN_RXQ_CTX_REAL_CNT_S				0
#define MS_LAN_RXQ_CTX_REAL_CNT_M				NSE_M(0x1FFF, 0)

	/* DATA[10] */
#define MS_LAN_RXQ_CTX_EST_CNT_S				0
#define MS_LAN_RXQ_CTX_EST_CNT_M				NSE_M(0x3FFF, 0)

} __packed;

struct nse_lan_rxq_ctx {
	union {
		u32 data[NSE_LAN_RXQ_CTX_LEN_IN_DWORD_MAX];
		struct nse_lan_rxq_ctx_amber amber;
		struct nse_lan_rxq_ctx_ms ms;
	};

	u32 ctx_data_len;

} __packed;

/* Tx Data Descriptor */
struct nse_tx_desc {
	__le64 buf_addr; /* Address of descriptor's data buf */

	__le64 cmd_type_offset_bsz;
/* for style unified clearness, intentionally not use GENMASK_ULL */

#define NSE_TXD_DD_S				0
#define NSE_TXD_DD_M				BIT_ULL(0)

#define NSE_TXD_DTYPE_S				1
#define NSE_TXD_DTYPE_M				BIT_ULL(1)

#define NSE_TXD_L4TYPE_S			2
#define NSE_TXD_L4TYPE_M			(0x3ULL << 2)

	#define NSE_TXD_L4TYPE_NONE			0x0ULL
	#define NSE_TXD_L4TYPE_TCP			0x1ULL
	#define NSE_TXD_L4TYPE_SCTP			0x2ULL
	#define NSE_TXD_L4TYPE_UDP			0x3ULL

#define NSE_TXD_IIPT_S				4
#define NSE_TXD_IIPT_M				(0x3ULL << 4)

	#define NSE_TXD_IIPT_NONE			0x0ULL
	#define NSE_TXD_IIPT_IPV6			0x1ULL
	#define NSE_TXD_IIPT_IPV4_NO_CSUM	0x2ULL
	#define NSE_TXD_IIPT_IPV4_CSUM		0x3ULL

#define NSE_TXD_L4LEN_S				6
#define NSE_TXD_L4LEN_M				(0xFULL << 6)

	#define NSE_TXD_L4LEN_MAX_IN_DWORD	0xF
	#define NSE_TXD_L4LEN_MAX_IN_BYTE	0x3C

#define NSE_TXD_EOP_S				10
#define NSE_TXD_EOP_M				BIT_ULL(10)

#define NSE_TXD_RS_S				11
#define NSE_TXD_RS_M				BIT_ULL(11)

#define NSE_TXD_L4CSUM_S			12
#define NSE_TXD_L4CSUM_M			BIT_ULL(12)

/* RSV: 77 - 1b --- previous IL2AG1, now move into tx-context-desc */
#define NSE_TXD_RSV_1_S				13
#define NSE_TXD_RSV_1_M				BIT_ULL(13)

#define NSE_TXD_LOCAL_DATA_S		14
#define NSE_TXD_LOCAL_DATA_M		BIT_ULL(14)

#define NSE_TXD_CC_S				15
#define NSE_TXD_CC_M				BIT_ULL(15)

#define NSE_TXD_TLEN_S				16
#define NSE_TXD_TLEN_M				(0x3FFFFULL << 16)

#define NSE_TXD_MACLEN_S			34
#define NSE_TXD_MACLEN_M			(0x7FULL << 34)

	#define NSE_TXD_CTX_MACLEN_MAX_IN_WORD	0x7F
	#define NSE_TXD_CTX_MACLEN_MAX_IN_BYTE	0xFE

#define NSE_TXD_IPLEN_S				41
#define NSE_TXD_IPLEN_M				(0x7FULL << 41)

	#define NSE_TXD_IPLEN_MAX_IN_DWORD	0x7F
	#define NSE_TXD_IPLEN_MAX_IN_BYTE	0x1FC

/* RSV: 113:112 - 2b */
#define NSE_TXD_RSV_2_S				48
#define NSE_TXD_RSV_2_M				(0x3ULL << 48)

#define NSE_TXD_BSIZE_S				50
#define NSE_TXD_BSIZE_M				(0x3FFFULL << 50)
} __packed;

/* Tx Context Descriptor */
struct nse_tx_ctx_desc {
	__le32 tunneling_params;
#define NSE_TXD_CTX_EIPT_S			0
#define NSE_TXD_CTX_EIPT_M			NSE_M(0x3, 0)

	#define NSE_TXD_CTX_EIPT_NONE			0x0
	#define NSE_TXD_CTX_EIPT_IPV6			0x1
	#define NSE_TXD_CTX_EIPT_IPV4_NO_CSUM	0x2
	#define NSE_TXD_CTX_EIPT_IPV4_CSUM		0x3

#define NSE_TXD_CTX_EIPLEN_S		2
#define NSE_TXD_CTX_EIPLEN_M		NSE_M(0x7F, 2)

	#define NSE_TXD_CTX_EIPLEN_MAX_IN_DWORD	0x7F
	#define NSE_TXD_CTX_EIPLEN_MAX_IN_BYTE	0x1FC

#define NSE_TXD_CTX_L4TUNT_S		9
#define NSE_TXD_CTX_L4TUNT_M		NSE_M(0x3, 9)

	#define NSE_TXD_CTX_L4TUNT_NONE		0x0
	#define NSE_TXD_CTX_L4TUNT_UDP		0x1
	#define NSE_TXD_CTX_L4TUNT_GRE		0x2
	#define NSE_TXD_CTX_L4TUNT_RSV		0x3

/* rsv: 11 - 1b */

#define NSE_TXD_CTX_L4TUNLEN_S		12
#define NSE_TXD_CTX_L4TUNLEN_M		NSE_M(0x7F, 12)

	#define NSE_TXD_CTX_L4TUNLEN_MAX_IN_WORD	0x7F
	#define NSE_TXD_CTX_L4TUNLEN_MAX_IN_BYTE	0xFE

#define NSE_TXD_CTX_DECTTL_S		19
#define NSE_TXD_CTX_DECTTL_M		NSE_M(0xF, 19)

#define NSE_TXD_CTX_L4T_CS_S		23
#define NSE_TXD_CTX_L4T_CS_M		BIT(23)

/* rsv: 31:24 - 8 b */

	__le16 l2tag2;

	__le16 control;
#define NSE_TXD_CTX_TSEC_S			0
#define NSE_TXD_CTX_TSEC_M			BIT(0)

#define NSE_TXD_CTX_PORTID_S		1
#define NSE_TXD_CTX_PORTID_M		NSE_M(0x3, 1)

/* rsv: 51 - 1 b */

#define NSE_TXD_CTX_CRCP_S			4
#define NSE_TXD_CTX_CRCP_M			BIT(4)

#define NSE_TXD_CTX_TLS_S			5
#define NSE_TXD_CTX_TLS_M			BIT(5)

#define NSE_TXD_CTX_TX_MD_S			6
#define NSE_TXD_CTX_TX_MD_M			NSE_M(0xF, 6)

#define NSE_TXD_CTX_TSYN_REG_S		10
#define NSE_TXD_CTX_TSYN_REG_M		NSE_M(0x3F, 10)

	__le64 qw1;
/* for style unified clearness, intentionally not use GENMASK_ULL */

#define NSE_TXD_CTX_DTYPE_S			1
#define NSE_TXD_CTX_DTYPE_M			BIT_ULL(1)

#define NSE_TXQ_CTX_PORT_VLD_S		2
#define NSE_TXQ_CTX_PORT_VLD_M		BIT_ULL(2)

#define NSE_TXQ_CTX_PORT_LOCK_S		3
#define NSE_TXQ_CTX_PORT_LOCK_M		BIT_ULL(3)

#define NSE_TXD_CTX_TSO_S			4
#define NSE_TXD_CTX_TSO_M			BIT_ULL(4)

#define NSE_TXD_CTX_TSYN_S			5
#define NSE_TXD_CTX_TSYN_M			BIT_ULL(5)

#define NSE_TXD_CTX_IL2TAG2_S		6
#define NSE_TXD_CTX_IL2TAG2_M		BIT_ULL(6)

#define NSE_TXD_CTX_IL2TAG_IL2H_S	7
#define NSE_TXD_CTX_IL2TAG_IL2H_M	BIT_ULL(7)

#define NSE_TXD_CTX_SWITCH_S		8
#define NSE_TXD_CTX_SWITCH_M		(0x3ULL << 8)

	#define NSE_TXD_CTX_SWITCH_NONE			0x0ULL
	#define NSE_TXD_CTX_SWITCH_UPLINK		0x1ULL
	#define NSE_TXD_CTX_SWITCH_LOCAL		0x2ULL
	#define NSE_TXD_CTX_SWITCH_VSI			0x3ULL

#define NSE_TXD_CTX_DEST_QUEUE_VLD_S	10
#define NSE_TXD_CTX_DEST_QUEUE_VLD_M	BIT_ULL(10)

#define NSE_TXD_CTX_DEST_QUEUE_S	11
#define NSE_TXD_CTX_DEST_QUEUE_M	(0x3FFULL << 11)

#define NSE_TXD_CTX_DEST_VSI_S		21
#define NSE_TXD_CTX_DEST_VSI_M		(0xFFULL << 21)

/* rsv: 93 - 1 b */

#define NSE_TXD_CTX_L2TAG1_S		30
#define NSE_TXD_CTX_L2TAG1_M		(0xFFFFULL << 30)

#define NSE_TXD_CTX_IL2TAG1_S		46
#define NSE_TXD_CTX_IL2TAG1_M		BIT_ULL(46)

/* rsv: 113:111 - 3 b */

#define NSE_TXD_CTX_MSS_S			50
#define NSE_TXD_CTX_MSS_M			(0x3FFFULL << 50)

	#define NSE_TXD_CTX_MSS_MIN			88
	#define NSE_TXD_CTX_MSS_MAX			8088

} __packed;

/* !!!NOTE: MUST use with NSE_TXD_DTYPE_S or NSE_TXD_CTX_DTYPE_S */
enum nse_tx_desc_dtype_value {
	NSE_TX_DESC_DTYPE_DATA		= 0x0ULL,
	NSE_TX_DESC_DTYPE_CTX		= 0x1ULL,
};

/* Tx CompletionQ Descriptor */
struct nse_lan_txcq_desc {
	__le32 data;

#define NSE_LAN_TXCQD_TXQ_ID_S			0
#define NSE_LAN_TXCQD_TXQ_ID_M			NSE_M(0x3FF, 0)

/* rsv: 10 ~ 13: 4 b */

/* rsv: 14: 1 b */

#define NSE_LAN_TXCQD_GENERATION_S		15
#define NSE_LAN_TXCQD_GENERATION_M		BIT(15)

#define NSE_LAN_TXCQD_TX_HEAD_S		16
#define NSE_LAN_TXCQD_TX_HEAD_M		NSE_M(0x1FFF, 16)

#define NSE_LAN_TXCQD_COMPLETION_TYPE_S		29
#define NSE_LAN_TXCQD_COMPLETION_TYPE_M		NSE_M(0x7, 29)

	#define NSE_LAN_TXCQD_COMPLETION_TYPE_ITR		0x0
	#define NSE_LAN_TXCQD_COMPLETION_TYPE_RS		0x1

} __packed;

/* match <nse_adminq_cmd.h> __le32 ctx_data[32] */
#define NSE_LAN_TXQ_CTX_LEN_IN_DWORD_MAX		32

#define NSE_LAN_TXQ_CTX_LEN_IN_DWORD_AMBER		15
#define NSE_LAN_TXQ_CTX_LEN_IN_DWORD_MS			11

struct nse_lan_txq_ctx_amber {
	u32 data[NSE_LAN_TXQ_CTX_LEN_IN_DWORD_AMBER];

	/* DATA[0]: BASE_low */
/* BASE is in 16-byte units, to fit virtio requirement, not 128-byte unit */
#define AMBER_LAN_TXQ_BASE_SHIFT			4
#define AMBER_LAN_TXQ_CTX_BASE_LOW_S			0
#define AMBER_LAN_TXQ_CTX_BASE_LOW_M			NSE_M(0xFFFFFFFF, 0)

	/* DATA[1]: BASE_high, Port_id, Port_lock, Port_vld */
#define AMBER_LAN_TXQ_CTX_PORT_VLD_S			31
#define AMBER_LAN_TXQ_CTX_PORT_VLD_M			BIT(31)

#define AMBER_LAN_TXQ_CTX_PORT_LOCK_S		30
#define AMBER_LAN_TXQ_CTX_PORT_LOCK_M		BIT(30)

#define AMBER_LAN_TXQ_CTX_PORT_ID_S			28
#define AMBER_LAN_TXQ_CTX_PORT_ID_M			NSE_M(0x3, 28)

#define AMBER_LAN_TXQ_CTX_BASE_HIGH_S		0
#define AMBER_LAN_TXQ_CTX_BASE_HIGH_M		NSE_M(0xFFFFFFF, 0)

	/* DATA[2]: TC, SRC_VSI, TSYN_ENA, CPUID, WB_mode, TPHRDdesc, TPHRDdata, TPHWRdesc */
#define AMBER_LAN_TXQ_CTX_TPHWRDESC_S		27
#define AMBER_LAN_TXQ_CTX_TPHWRDESC_M		BIT(27)

#define AMBER_LAN_TXQ_CTX_TPHRDDATA_S		26
#define AMBER_LAN_TXQ_CTX_TPHRDDATA_M		BIT(26)

#define AMBER_LAN_TXQ_CTX_TPHRDDESC_S		25
#define AMBER_LAN_TXQ_CTX_TPHRDDESC_M		BIT(25)

#define AMBER_LAN_TXQ_CTX_WB_MODE_S			24
#define AMBER_LAN_TXQ_CTX_WB_MODE_M			BIT(24)

	#define AMBER_LAN_TXQ_CTX_WB_MODE_DESCRIPTOR		0x0
	#define AMBER_LAN_TXQ_CTX_WB_MODE_CMPQ			0x1

#define AMBER_LAN_TXQ_CTX_CPUID_S			16
#define AMBER_LAN_TXQ_CTX_CPUID_M			NSE_M(0xFF, 16)

#define AMBER_LAN_TXQ_CTX_TSYN_ENA_S			12
#define AMBER_LAN_TXQ_CTX_TSYN_ENA_M			BIT(12)

#define AMBER_LAN_TXQ_CTX_SRC_VSI_S			4
#define AMBER_LAN_TXQ_CTX_SRC_VSI_M			NSE_M(0xFF, 4)

#define AMBER_LAN_TXQ_CTX_TC_S				0
#define AMBER_LAN_TXQ_CTX_TC_M				NSE_M(0x7, 0)

	/* DATA[3]: CMPQ_ID, Qnum_in_func */

#define AMBER_LAN_TXQ_CTX_QNUM_IN_FUNC_S		8
#define AMBER_LAN_TXQ_CTX_QNUM_IN_FUNC_M		NSE_M(0x3FF, 8)

#define AMBER_LAN_TXQ_CTX_CMPQ_ID_S			0
#define AMBER_LAN_TXQ_CTX_CMPQ_ID_M			NSE_M(0xFF, 0)

	/* DATA[4]: Queue length, TSO_enabled_queue, Queue_type, LL */
#define AMBER_LAN_TXQ_CTX_LL_S				18
#define AMBER_LAN_TXQ_CTX_LL_M				BIT(18)

#define AMBER_LAN_TXQ_CTX_QTYPE_S			17
#define AMBER_LAN_TXQ_CTX_QTYPE_M			BIT(17)

	#define AMBER_LAN_TXQ_CTX_QTYPE_NATIVE		0x0
	#define AMBER_LAN_TXQ_CTX_QTYPE_VIRTIO		0x1

#define AMBER_LAN_TXQ_CTX_TSO_ENA_QUEUE_S	16
#define AMBER_LAN_TXQ_CTX_TSO_ENA_QUEUE_M	BIT(16)

#define AMBER_LAN_TXQ_CTX_QLEN_S				0
#define AMBER_LAN_TXQ_CTX_QLEN_M				NSE_M(0x1FFF, 0)

	/*  DATA[5]: MSIx_idx, Cause_en, PF_NUM, Local_desc, desc_coalesce_en, statistic_en,
	 * statistic_cnt_id
	 */
#define AMBER_LAN_TXQ_CTX_STATS_CNT_ID_S		18
#define AMBER_LAN_TXQ_CTX_STATS_CNT_ID_M		NSE_M(0xF, 18)

#define AMBER_LAN_TXQ_CTX_STATS_EN_S			17
#define AMBER_LAN_TXQ_CTX_STATS_EN_M			BIT(17)

#define AMBER_LAN_TXQ_CTX_DESC_COALESCE_EN_S	16
#define AMBER_LAN_TXQ_CTX_DESC_COALESCE_EN_M	BIT(16)

#define AMBER_LAN_TXQ_CTX_LOCAL_DESC_S		14
#define AMBER_LAN_TXQ_CTX_LOCAL_DESC_M		BIT(14)

#define AMBER_LAN_TXQ_CTX_CAUSE_EN_S			12
#define AMBER_LAN_TXQ_CTX_CAUSE_EN_M			BIT(12)

#define AMBER_LAN_TXQ_CTX_PF_ID_S			10
#define AMBER_LAN_TXQ_CTX_PF_ID_M			NSE_M(0x3, 10)

#define AMBER_LAN_TXQ_CTX_MSIX_IDX_S			0
#define AMBER_LAN_TXQ_CTX_MSIX_IDX_M			NSE_M(0x3FF, 0)

	/* DATA[6]: vis_addr_lsb */
	/* DATA[7]: vis_addr_msb */
#define AMBER_LAN_TXQ_CTX_VIS_ADDR_L_S		0
#define AMBER_LAN_TXQ_CTX_VIS_ADDR_L_M		NSE_M(0xFFFFFFFF, 0)

#define AMBER_LAN_TXQ_CTX_VIS_ADDR_H_S		0
#define AMBER_LAN_TXQ_CTX_VIS_ADDR_H_M		NSE_M(0xFFFFFFFF, 0)

	/* DATA[8]: wptr, driver_wrap_cnt, wbptr, device_wrap_cnt */
#define AMBER_LAN_TXQ_CTX_DEV_WRAP_CNT_S		31
#define AMBER_LAN_TXQ_CTX_DEV_WRAP_CNT_M		BIT(31)

#define AMBER_LAN_TXQ_CTX_WBPTR_S			16
#define AMBER_LAN_TXQ_CTX_WBPTR_M			NSE_M(0x1FFF, 16)

#define AMBER_LAN_TXQ_CTX_DRV_WRAP_CNT_S		15
#define AMBER_LAN_TXQ_CTX_DRV_WRAP_CNT_M		BIT(15)

#define AMBER_LAN_TXQ_CTX_WPTR_S				0
#define AMBER_LAN_TXQ_CTX_WPTR_M				NSE_M(0x1FFF, 0)

	/* DATA[9]: fptr, rptr */
#define AMBER_LAN_TXQ_CTX_RPTR_S				16
#define AMBER_LAN_TXQ_CTX_RPTR_M				NSE_M(0x1FFF, 16)

#define AMBER_LAN_TXQ_CTX_FPTR_S				0
#define AMBER_LAN_TXQ_CTX_FPTR_M				NSE_M(0x1FFF, 0)

	/* DATA[10] */
#define AMBER_LAN_TXQ_CTX_RCV_QUANTA_CNT_UNFL_S		31
#define AMBER_LAN_TXQ_CTX_RCV_QUANTA_CNT_UNFL_M		BIT(31)

#define AMBER_LAN_TXQ_CTX_RCV_QUANTA_BYTE_S			0
#define AMBER_LAN_TXQ_CTX_RCV_QUANTA_BYTE_M			NSE_M(0x1FFFFF, 0)

	/* DATA[11] */
#define AMBER_LAN_TXQ_CTX_ADJ_CNT_S				0
#define AMBER_LAN_TXQ_CTX_ADJ_CNT_M				NSE_M(0x1FFFFF, 0)

	/* DATA[12] */
#define AMBER_LAN_TXQ_CTX_ACC_QUANTA_CONSUME_DESC_CNT_S		16
#define AMBER_LAN_TXQ_CTX_ACC_QUANTA_CONSUME_DESC_CNT_M		NSE_M(0x3FFF, 16)

#define AMBER_LAN_TXQ_CTX_ACC_QUANTA_CNT_S		8
#define AMBER_LAN_TXQ_CTX_ACC_QUANTA_CNT_M		NSE_M(0x7F, 8)

#define AMBER_LAN_TXQ_CTX_PREDICT_DESC_NUM_S		0
#define AMBER_LAN_TXQ_CTX_PREDICT_DESC_NUM_M		NSE_M(0xFF, 0)

	/* DATA[13] */
#define AMBER_LAN_TXQ_CTX_SUM_DESC_BSIZE_S		0
#define AMBER_LAN_TXQ_CTX_SUM_DESC_BSIZE_M		NSE_M(0x3FFFF, 0)

	/* DATA[14] */
#define AMBER_LAN_TXQ_CTX_PENDING_BYTE_S			0
#define AMBER_LAN_TXQ_CTX_PENDING_BYTE_M			NSE_M(0x3FFFF, 0)

} __packed;

struct nse_lan_txq_ctx_ms {
	u32 data[NSE_LAN_TXQ_CTX_LEN_IN_DWORD_MS];

	/* DATA[0]: BASE_low */
/* BASE is in 16-byte units, to fit virtio requirement, not 128-byte unit */
#define MS_LAN_TXQ_BASE_SHIFT			4
#define MS_LAN_TXQ_CTX_BASE_LOW_S			0
#define MS_LAN_TXQ_CTX_BASE_LOW_M			NSE_M(0xFFFFFFFF, 0)

	/* DATA[1]: BASE_high */
#define MS_LAN_TXQ_CTX_BASE_HIGH_S		0
#define MS_LAN_TXQ_CTX_BASE_HIGH_M		NSE_M(0xFFFFFFF, 0)

	/* DATA[2]: TC, SRC_VSI, TSYN_ENA, CPUID, WB_mode, TPHRDdesc, TPHRDdata, TPHWRdesc */
#define MS_LAN_TXQ_CTX_TPHWRDESC_S		27
#define MS_LAN_TXQ_CTX_TPHWRDESC_M		BIT(27)

#define MS_LAN_TXQ_CTX_TPHRDDATA_S		26
#define MS_LAN_TXQ_CTX_TPHRDDATA_M		BIT(26)

#define MS_LAN_TXQ_CTX_TPHRDDESC_S		25
#define MS_LAN_TXQ_CTX_TPHRDDESC_M		BIT(25)

#define MS_LAN_TXQ_CTX_WB_MODE_S			24
#define MS_LAN_TXQ_CTX_WB_MODE_M			BIT(24)

	#define MS_LAN_TXQ_CTX_WB_MODE_DESCRIPTOR		0x0
	#define MS_LAN_TXQ_CTX_WB_MODE_CMPQ			0x1

#define MS_LAN_TXQ_CTX_CPUID_S			16
#define MS_LAN_TXQ_CTX_CPUID_M			NSE_M(0xFF, 16)

#define MS_LAN_TXQ_CTX_TSYN_ENA_S			12
#define MS_LAN_TXQ_CTX_TSYN_ENA_M			BIT(12)

#define MS_LAN_TXQ_CTX_SRC_VSI_S			4
#define MS_LAN_TXQ_CTX_SRC_VSI_M			NSE_M(0x7, 4)

#define MS_LAN_TXQ_CTX_TC_S				0
#define MS_LAN_TXQ_CTX_TC_M				NSE_M(0x7, 0)

	/* DATA[3]: CMPQ_ID, Qnum_in_func */
#define MS_LAN_TXQ_CTX_QNUM_IN_FUNC_S		8
#define MS_LAN_TXQ_CTX_QNUM_IN_FUNC_M		NSE_M(0x1F, 8)

#define MS_LAN_TXQ_CTX_CMPQ_ID_S			0
#define MS_LAN_TXQ_CTX_CMPQ_ID_M			NSE_M(0xFF, 0)

	/* DATA[4]: Queue length, TSO_enabled_queue, Queue_type, LL */
#define MS_LAN_TXQ_CTX_LL_S				18
#define MS_LAN_TXQ_CTX_LL_M				BIT(18)

#define MS_LAN_TXQ_CTX_QTYPE_S			17
#define MS_LAN_TXQ_CTX_QTYPE_M			BIT(17)

	#define MS_LAN_TXQ_CTX_QTYPE_NATIVE		0x0
	#define MS_LAN_TXQ_CTX_QTYPE_VIRTIO		0x1

#define MS_LAN_TXQ_CTX_TSO_ENA_QUEUE_S	16
#define MS_LAN_TXQ_CTX_TSO_ENA_QUEUE_M	BIT(16)

#define MS_LAN_TXQ_CTX_QLEN_S				0
#define MS_LAN_TXQ_CTX_QLEN_M				NSE_M(0x1FFF, 0)

	/*  DATA[5]: MSIx_idx, Cause_en, PF_NUM, Local_desc, desc_coalesce_en, statistic_en,
	 * statistic_cnt_id
	 */
#define MS_LAN_TXQ_CTX_DESC_COALESCE_EN_S	16
#define MS_LAN_TXQ_CTX_DESC_COALESCE_EN_M	BIT(16)

#define MS_LAN_TXQ_CTX_CAUSE_EN_S			12
#define MS_LAN_TXQ_CTX_CAUSE_EN_M			BIT(12)

#define MS_LAN_TXQ_CTX_PF_ID_S			10
#define MS_LAN_TXQ_CTX_PF_ID_M			NSE_M(0x1, 10)

#define MS_LAN_TXQ_CTX_MSIX_IDX_S			0
#define MS_LAN_TXQ_CTX_MSIX_IDX_M			NSE_M(0x3FF, 0)

	/* DATA[6]: not used in ms */
	/* DATA[7]: not used in ms */

	/* DATA[8]: wptr, driver_wrap_cnt, wbptr, device_wrap_cnt */
#define MS_LAN_TXQ_CTX_DEV_WRAP_CNT_S		31
#define MS_LAN_TXQ_CTX_DEV_WRAP_CNT_M		BIT(31)

#define MS_LAN_TXQ_CTX_WBPTR_S			16
#define MS_LAN_TXQ_CTX_WBPTR_M			NSE_M(0x1FFF, 16)

#define MS_LAN_TXQ_CTX_DRV_WRAP_CNT_S		15
#define MS_LAN_TXQ_CTX_DRV_WRAP_CNT_M		BIT(15)

#define MS_LAN_TXQ_CTX_WPTR_S				0
#define MS_LAN_TXQ_CTX_WPTR_M				NSE_M(0x1FFF, 0)

	/* DATA[9]: fptr, rptr */
#define MS_LAN_TXQ_CTX_RPTR_S				16
#define MS_LAN_TXQ_CTX_RPTR_M				NSE_M(0x1FFF, 16)

#define MS_LAN_TXQ_CTX_FPTR_S				0
#define MS_LAN_TXQ_CTX_FPTR_M				NSE_M(0x1FFF, 0)

	/* DATA[10] */
#define MS_LAN_TXQ_CTX_RCV_QUANTA_CNT_UNFL_S		31
#define MS_LAN_TXQ_CTX_RCV_QUANTA_CNT_UNFL_M		BIT(31)

#define MS_LAN_TXQ_CTX_RCV_QUANTA_BYTE_S			0
#define MS_LAN_TXQ_CTX_RCV_QUANTA_BYTE_M			NSE_M(0x1FFFFF, 0)

} __packed;

struct nse_lan_txq_ctx {
	union {
		u32 data[NSE_LAN_TXQ_CTX_LEN_IN_DWORD_MAX];
		struct nse_lan_txq_ctx_amber amber;
		struct nse_lan_txq_ctx_ms ms;
	};

	u32 ctx_data_len;

} __packed;

#define NSE_LAN_TXCQ_CTX_LEN_IN_DWORD	5

struct nse_lan_txcq_ctx {
	u32 data[NSE_LAN_TXCQ_CTX_LEN_IN_DWORD];

	/* DATA[0]: BASE_low */
/* BASE is in 128-byte unit, unlike RXQ/TXQ which are 16-byte unit */
#define LAN_TXCQ_BASE_SHIFT			7
#define LAN_TXCQ_CTX_BASE_LOW_S			0
#define LAN_TXCQ_CTX_BASE_LOW_M			NSE_M(0xFFFFFFFF, 0)

	/* DATA[1]: BASE_high */
#define LAN_TXCQ_CTX_BASE_HIGH_S			0
#define LAN_TXCQ_CTX_BASE_HIGH_M			NSE_M(0x1FFFFFF, 0)

	/* DATA[2]: Queue length */
/* CQ length is in 16 desc unit, unlike RXQ/TXQ which are 1 desc unit */
#define LAN_TXCQ_QLEN_SHIFT			4
	#define LAN_TXCQ_QLEN_MULTIPLE			16
#define LAN_TXCQ_CTX_QLEN_S				0
#define LAN_TXCQ_CTX_QLEN_M				NSE_M(0x3FFFF, 0)

	/* DATA[3]: src_vsi, desc_coalesce_en, cause_en, msix_idx, tphwr_desc, cpuid */
#define LAN_TXCQ_CTX_SRC_VSI_S			24
#define LAN_TXCQ_CTX_SRC_VSI_M			NSE_M(0xFF, 24)

#define LAN_TXCQ_CTX_DESC_COALESCE_EN_S	23
#define LAN_TXCQ_CTX_DESC_COALESCE_EN_M	BIT(23)

#define LAN_TXCQ_CTX_CAUSE_EN_S			22
#define LAN_TXCQ_CTX_CAUSE_EN_M			BIT(22)

#define LAN_TXCQ_CTX_MSIX_IDX_S			12
#define LAN_TXCQ_CTX_MSIX_IDX_M			NSE_M(0x3FF, 12)

/* RSV: 3b */

#define LAN_TXCQ_CTX_TPHWRDESC_S			8
#define LAN_TXCQ_CTX_TPHWRDESC_M			BIT(8)

#define LAN_TXCQ_CTX_CPUID_S				0
#define LAN_TXCQ_CTX_CPUID_M				NSE_M(0xFF, 0)

	/* DATA[4]: cq_wptr, generation */
#define LAN_TXCQ_CTX_WPTR_S				1
#define LAN_TXCQ_CTX_WPTR_M				NSE_M(0x3FFFFF, 1)

#define LAN_TXCQ_CTX_GENERATION_S			0
#define LAN_TXCQ_CTX_GENERATION_M			BIT(0)

} __packed;

struct nse_rx_ptype_decoded {
	u32 known:1;
	u32 outer_ip:1;
	u32 outer_ip_ver:2;
	u32 outer_frag:1;
	u32 tunnel_type:3;
	u32 tunnel_end_prot:2;
	u32 tunnel_end_frag:1;
	u32 inner_prot:4;
	u32 payload_layer:3;
};

enum nse_rx_ptype_outer_ip {
	NSE_RX_PTYPE_OUTER_L2	= 0,
	NSE_RX_PTYPE_OUTER_IP	= 1,
};

enum nse_rx_ptype_outer_ip_ver {
	NSE_RX_PTYPE_OUTER_NONE	= 0,
	NSE_RX_PTYPE_OUTER_IPV4	= 1,
	NSE_RX_PTYPE_OUTER_IPV6	= 2,
};

enum nse_rx_ptype_outer_fragmented {
	NSE_RX_PTYPE_NOT_FRAG	= 0,
	NSE_RX_PTYPE_FRAG	= 1,
};

enum nse_rx_ptype_tunnel_type {
	NSE_RX_PTYPE_TUNNEL_NONE		= 0,
	NSE_RX_PTYPE_TUNNEL_IP_IP		= 1,
	NSE_RX_PTYPE_TUNNEL_IP_GRENAT		= 2,
	NSE_RX_PTYPE_TUNNEL_IP_GRENAT_MAC	= 3,
	NSE_RX_PTYPE_TUNNEL_IP_GRENAT_MAC_VLAN	= 4,
};

enum nse_rx_ptype_tunnel_end_prot {
	NSE_RX_PTYPE_TUNNEL_END_NONE	= 0,
	NSE_RX_PTYPE_TUNNEL_END_IPV4	= 1,
	NSE_RX_PTYPE_TUNNEL_END_IPV6	= 2,
};

enum nse_rx_ptype_inner_prot {
	NSE_RX_PTYPE_INNER_PROT_NONE		= 0,
	NSE_RX_PTYPE_INNER_PROT_UDP		= 1,
	NSE_RX_PTYPE_INNER_PROT_TCP		= 2,
	NSE_RX_PTYPE_INNER_PROT_SCTP		= 3,
	NSE_RX_PTYPE_INNER_PROT_ICMP		= 4,
	NSE_RX_PTYPE_INNER_PROT_TIMESYNC	= 5,
};

enum nse_rx_ptype_payload_layer {
	NSE_RX_PTYPE_PAYLOAD_LAYER_NONE	= 0,
	NSE_RX_PTYPE_PAYLOAD_LAYER_PAY2	= 1,
	NSE_RX_PTYPE_PAYLOAD_LAYER_PAY3	= 2,
	NSE_RX_PTYPE_PAYLOAD_LAYER_PAY4	= 3,
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
#define NSE_PTT(PTYPE, OUTER_IP, OUTER_IP_VER, OUTER_FRAG, T, TE, TEF, I, PL)\
	[PTYPE] = { \
		1, \
		NSE_RX_PTYPE_OUTER_##OUTER_IP, \
		NSE_RX_PTYPE_OUTER_##OUTER_IP_VER, \
		NSE_RX_PTYPE_##OUTER_FRAG, \
		NSE_RX_PTYPE_TUNNEL_##T, \
		NSE_RX_PTYPE_TUNNEL_END_##TE, \
		NSE_RX_PTYPE_##TEF, \
		NSE_RX_PTYPE_INNER_PROT_##I, \
		NSE_RX_PTYPE_PAYLOAD_LAYER_##PL }

#define NSE_PTT_UNUSED_ENTRY(PTYPE)[PTYPE] = { 0, 0, 0, 0, 0, 0, 0, 0, 0 }

/* shorter macros makes the table fit but are terse */
#define NSE_RX_PTYPE_NOF		NSE_RX_PTYPE_NOT_FRAG
#define NSE_RX_PTYPE_FRG		NSE_RX_PTYPE_FRAG
#define NSE_RX_PTYPE_INNER_PROT_TS	NSE_RX_PTYPE_INNER_PROT_TIMESYNC

extern const struct nse_rx_ptype_decoded nse_ptype_lkup[256];

static inline struct nse_rx_ptype_decoded nse_decode_rx_desc_ptype(u8 ptype)
{
	return nse_ptype_lkup[ptype];
}

/* some wellknown ptype */
#define NSE_PTYPE_MAC_IPV4_UDP_PAY4		35
#define NSE_PTYPE_MAC_IPV4_TCP_PAY4		36
#define NSE_PTYPE_MAC_IPV4_SCTP_PAY4	37
#define NSE_PTYPE_MAC_IPV4_ICMP_PAY4	38
#define NSE_PTYPE_MAC_IPV6_UDP_PAY4		43
#define NSE_PTYPE_MAC_IPV6_TCP_PAY4		44
#define NSE_PTYPE_MAC_IPV6_SCTP_PAY4	45
#define NSE_PTYPE_MAC_IPV6_ICMP_PAY4	46

#endif /* _NSE_LAN_TX_RX_H_ */

