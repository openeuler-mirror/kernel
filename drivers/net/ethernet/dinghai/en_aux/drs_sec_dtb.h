/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef DRS_SEC_DTB_H
#define DRS_SEC_DTB_H
#include <linux/types.h>
#include <linux/io.h>

typedef unsigned long long u64;

#define BITWIDTH1 ((u32)0x00000001)
#define BITWIDTH2 ((u32)0x00000003)
#define BITWIDTH3 ((u32)0x00000007)
#define BITWIDTH4 ((u32)0x0000000f)
#define BITWIDTH5 ((u32)0x0000001f)
#define BITWIDTH6 ((u32)0x0000003f)
#define BITWIDTH7 ((u32)0x0000007f)
#define BITWIDTH8 ((u32)0x000000ff)
#define BITWIDTH9 ((u32)0x000001ff)
#define BITWIDTH10 ((u32)0x000003ff)
#define BITWIDTH11 ((u32)0x000007ff)
#define BITWIDTH12 ((u32)0x00000fff)
#define BITWIDTH13 ((u32)0x00001fff)
#define BITWIDTH14 ((u32)0x00003fff)
#define BITWIDTH15 ((u32)0x00007fff)
#define BITWIDTH16 ((u32)0x0000ffff)
#define BITWIDTH17 ((u32)0x0001ffff)
#define BITWIDTH18 ((u32)0x0003ffff)
#define BITWIDTH19 ((u32)0x0007ffff)
#define BITWIDTH20 ((u32)0x000fffff)
#define BITWIDTH21 ((u32)0x001fffff)
#define BITWIDTH22 ((u32)0x003fffff)
#define BITWIDTH23 ((u32)0x007fffff)
#define BITWIDTH24 ((u32)0x00ffffff)
#define BITWIDTH25 ((u32)0x01ffffff)
#define BITWIDTH26 ((u32)0x03ffffff)
#define BITWIDTH27 ((u32)0x07ffffff)
#define BITWIDTH28 ((u32)0x0fffffff)
#define BITWIDTH29 ((u32)0x1fffffff)
#define BITWIDTH30 ((u32)0x3fffffff)
#define BITWIDTH31 ((u32)0x7fffffff)
#define BITWIDTH32 ((u32)0xffffffff)

#define PUB_OK (0)
#define PUB_ERROR (0xffffffff)

#define BTTL_PRINTF(fmt, arg...) DH_LOG_INFO(MODULE_SEC, fmt, ##arg)
#define BTTL_PUB_PRINT_ERROR(fmt, arg...) DH_LOG_ERR(MODULE_SEC, fmt, ##arg)

#define PUB_BIT_SET(reg, bit) ((reg) = ((reg) | (1u << (bit))))

#define PUB_BIT_CLEAR(reg, bit) ((reg) = ((reg) & (~(1u << (bit)))))

#define PUB_GET_BIT_VAL(reg, bit) (((reg) >> (bit)) & 1u)

#define PUB_IS_BIT_SET(reg, pos) (((reg) & (1u << (pos))) != 0x0u)

#define PUB_IS_BIT_CLEAR(reg, pos) (((reg) & (1u << (pos))) == 0x0u)

#define PUB_BIT_INSR(reg, bit, val) ((reg) = (((reg) & (~(1u << (bit)))) | (((val)&1u) << (bit))))

#define PUB_BIT_FIELD_MASK_GET64(bitoff, bitfieldlen) \
	((((u64)0x01 << (bitfieldlen)) - 1) << (bitoff))

#define PUB_BIT_FIELD_GET64(val, bitoff, bitfieldlen) \
	((val)&PUB_BIT_FIELD_MASK_GET64(bitoff, bitfieldlen))

#define PUB_BIT_FIELD_SET64(var, val, bitoff, bitlen) \
	((var) = (((var) & (~PUB_BIT_FIELD_MASK_GET64(bitoff, bitlen))) | (((u64)val) << (bitoff))))

#define PUB_BIT_FIELD_RIGHT_JUST_GET64(val, bitoff, bitfieldlen) \
	(((val) >> (bitoff)) & (((u64)0x01 << (bitfieldlen)) - 1))

#define PUB_SWAP16(x) ((u16)((((x) >> 8) & 0xffu) | (((x)&0xffu) << 8)))

#define PUB_SWAP32(x)                                                                           \
	((u32)((((u32)(x) & (u32)0x000000ffUL) << 24) | (((u32)(x) & (u32)0x0000ff00UL) << 8) | \
	       (((u32)(x) & (u32)0x00ff0000UL) >> 8) | (((u32)(x) & (u32)0xff000000UL) >> 24)))

#define PUB_SWAP64(x)                                           \
	((u64)((((u64)(x) & (u64)0x00000000000000ffUL) << 56) | \
	       (((u64)(x) & (u64)0x000000000000ff00UL) << 40) | \
	       (((u64)(x) & (u64)0x0000000000ff0000UL) << 24) | \
	       (((u64)(x) & (u64)0x00000000ff000000UL) << 8) |  \
	       (((u64)(x) & (u64)0x000000ff00000000UL) >> 8) |  \
	       (((u64)(x) & (u64)0x0000ff0000000000UL) >> 24) | \
	       (((u64)(x) & (u64)0x00ff000000000000UL) >> 40) | \
	       (((u64)(x) & (u64)0xff00000000000000UL) >> 56)))

#define PUB_LE_TO_NET16(x) PUB_SWAP16(x)
#define PUB_LE_TO_NET32(x) PUB_SWAP32(x)
#define PUB_LE_TO_NET64(x) PUB_SWAP64(x)
#define PUB_DE_TO_NET16(x) (x)
#define PUB_DE_TO_NET32(x) (x)
#define PUB_DE_TO_NET64(x) (x)

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__

#define PUB_LE_TO_HOST16(x) PUB_SWAP16(x)
#define PUB_LE_TO_HOST32(x) PUB_SWAP32(x)
#define PUB_LE_TO_HOST64(x) PUB_SWAP64(x)
#define PUB_DE_TO_HOST16(x) (x)
#define PUB_DE_TO_HOST32(x) (x)
#define PUB_DE_TO_HOST64(x) (x)
#define PUB_HTON16(x) (x)
#define PUB_HTON32(x) (x)
#define PUB_HTON64(x) (x)
#define PUB_NTOH16(x) (x)
#define PUB_NTOH32(x) (x)
#define PUB_NTOH64(x) (x)

#else
#define PUB_LE_TO_HOST16(x) (x)
#define PUB_LE_TO_HOST32(x) (x)
#define PUB_LE_TO_HOST64(x) (x)
#define PUB_DE_TO_HOST16(x) PUB_SWAP16(x)
#define PUB_DE_TO_HOST32(x) PUB_SWAP32(x)
#define PUB_DE_TO_HOST64(x) PUB_SWAP64(x)
#define PUB_HTON16(x) PUB_SWAP16(x)
#define PUB_HTON32(x) PUB_SWAP32(x)
#define PUB_HTON64(x) PUB_SWAP64(x)
#define PUB_NTOH16(x) PUB_SWAP16(x)
#define PUB_NTOH32(x) PUB_SWAP32(x)
#define PUB_NTOH64(x) PUB_SWAP64(x)

#endif

/* vport
 * 15 |14 13 12 |     11    |10  9  8|7 6 5 4 3 2 1 0|
 * rsv| ep_id   |func_active|func_num|    vfunc_num  |
 */
#define VPORT_EPID_BT_START (12)
#define VPORT_EPID_BT_LEN (3)
#define VPORT_FUNC_ACTIVE_BT_START (11)
#define VPORT_FUNC_ACTIVE_BT_LEN (1)
#define VPORT_FUNC_NUM_BT_START (8)
#define VPORT_FUNC_NUM_BT_LEN (3)
#define VPORT_VFUNC_NUM_BT_START (0)
#define VPORT_VFUNC_NUM_BT_LEN (8)

#define PUB_READ_REG8(addr) readb(addr)
#define PUB_READ_REG16(addr) readw(addr)
//#define PUB_READ_REG32(addr) readl(addr)
#define PUB_READ_REG32(addr) readl((void __iomem *)(unsigned long)(addr))

#define PUB_WRITE_REG8(addr, val_8) writeb(val_8, addr)
#define PUB_WRITE_REG16(addr, val_16) writew(val_16, addr)
//#define PUB_WRITE_REG32(addr, val_32) writel(val_32, addr)
#define PUB_WRITE_REG32(addr, val_32) writel(val_32, (void __iomem *)(unsigned long)(addr))

#define REG_SEC_IDX_OFFSET (0x800000)

#define REG_SEC_TOP_DTB_OFFSET (0)

#define REG_SEC_CFG_QUEUE_DTB_ADDR_H_0_127(n) (REG_SEC_TOP_DTB_OFFSET + 0x0000 + n * 32)

#define REG_SEC_CFG_QUEUE_DTB_ADDR_L_0_127(n) (REG_SEC_TOP_DTB_OFFSET + 0x0004 + n * 32)

#define REG_SEC_CFG_QUEUE_DTB_LEN_0_127(n) (REG_SEC_TOP_DTB_OFFSET + 0x0008 + n * 32)

#define REG_SEC_INFO_QUEUE_BUF_SPACE_LEFT_0_127(n) (REG_SEC_TOP_DTB_OFFSET + 0x000C + n * 32)

#define REG_SEC_CFG_EPID_V_FUNC_NUM_0_127(n) (REG_SEC_TOP_DTB_OFFSET + 0x0010 + n * 32)

#define REG_SEC_DTB_QUEUE_LOCK_STATE_0_3(n) (REG_SEC_TOP_DTB_OFFSET + 0x4080 + n * 4)

enum E_CMDK_SEC_IPSEC_MODE {
	e_SEC_IPSEC_TRANSPORT_MODE = 0,
	e_SEC_IPSEC_TUNNEL_MODE,
	e_SEC_IPSEC_MODE_LAST,
};

enum E_CMDK_SEC_SA_DF_MODE {
	e_SEC_SA_DF_BYPASS_MODE = 0, /*00 bypass DF bit*/
	e_SEC_SA_DF_CLEAR_MODE, /*01 clear*/
	e_SEC_SA_DF_SET_MODE, /*10 set*/
	e_SEC_SA_DF_COPY_MODE, /*11 copy*/
	e_SEC_SA_DF_MODE_LAST,
};

enum E_CMDK_DTB_SA_CMD_TYPE {
	E_DTB_SA_CMD_FLOW_DOWN = 0,
	E_DTB_SA_CMD_DUMP,
	E_DTB_SA_CMD_LAST,
};

enum E_SA_TYPE {
	E_SATYPE_IN = 1,
	E_SATYPE_OUT,
	E_SATYPE_IN_AND_OUT = 3,
};

enum E_INLINE_TYPE {
	E_INLINE_IN,
	E_INLINE_OUT,
	E_INLINE_IN_AND_OUT,
};

enum E_CMDK_SEC_ENCRYP_MODE {
	e_SEC_ENCRYP_AH_MODE = 0,
	e_SEC_ENCRYP_ESP_AUTH_MODE,
	e_SEC_ENCRYP_ESP_ENCRYP_MODE,
	e_SEC_ENCRYP_ESP_AUTH_AND_ESP_ENCRYP_MODE,
	e_SEC_ENCRYP_ESP_COMBINED_MODE,
	e_SEC_ENCRYP_MODE_LAST,
};

enum E_CMDK_LIVETIME_TYPES {
	e_SEC_SA_LIVETIME_NONE_TYPE = 0, /*00 none*/
	e_SEC_SA_LIVETIME_TIME_TYPE,
	e_SEC_SA_LIVETIME_BYTE_TYPE,
	e_SEC_SA_LIVETIME_PKT_TYPE,
	e_SEC_SA_LIVETIME_TYPE_LAST,
};

#pragma pack(1)
struct IPV4_HEAD {
	u8 ip_headlen_version;
	u8 ip_tos;
	u16 usTotallen;

	u16 usIdentify;
	u16 ip_fragoff;

	u8 uclive_time;
	u8 ucProtocal;
	u16 usHeadChecksum;

	u32 udSrcIpAddr;
	u32 udDstIpAddr;
};
#pragma pack()

struct T_QUEUE_DTB_REG {
	u32 DtbAddrH;
	u32 DtbAddrL;
	u32 DtbCmd;
};

struct T_HAL_SA_DTB_HW_OUT {
	u32 udSPI;
	u32 udSaId;
	u16 usSaParam;
	u8 ucCiperID;
	u8 ucAuthID;
	u8 ucCipherkeyLen;
	u8 ucAuthkeyLen;
	u16 usFrag_State;

	u32 udESN;
	u32 udSN;
	u64 uddProcessedByteCnt;

	u32 udSalt;
	u32 udLifetimeSecMax;
	u64 uddLifetimByteCntMax;

	u8 ucProtocol;
	u8 ucTOS;
	u8 ucEsnFlag;
	u8 ucIpType;
	u32 udRSV0;
	u32 udRSV1;
	u32 udRSV2;

	u32 udSrcAddress0;
	u32 udSrcAddress1;
	u32 udSrcAddress2;
	u32 udSrcAddress3;

	u32 udDstAddress0;
	u32 udDstAddress1;
	u32 udDstAddress2;
	u32 udDstAddress3;

	u8 aucSaCipherKey[32];
	u8 aucSaAuthKey[128];
} __packed;

struct T_HAL_SA_DTB_HW_IN {
	u32 udSrcAddress0;
	u32 udSrcAddress1;
	u32 udSrcAddress2;
	u32 udSrcAddress3;

	u32 udDstAddress0;
	u32 udDstAddress1;
	u32 udDstAddress2;
	u32 udDstAddress3;

	u32 udSPI;
	u32 udSaId;
	u16 usSaParam;
	u8 ucCiperID;
	u8 ucAuthID;
	u8 ucCipherkeyLen;
	u8 ucAuthkeyLen;
	u16 usFrag_State;

	u32 udSalt;
	u32 udLifetimeSecMax;
	u64 uddLifetimByteCntMax;

	u8 ucProtocol;
	u8 ucTOS;
	u8 ucEsnFlag;
	u8 ucIpType;
	u16 usOutSaOffset;
	u16 udRSV0;
	u32 udOutSaId;
	u32 udRSV1;

	u8 aucBitmap[256];

	u32 udAntiWindowHigh;
	u32 udAntiWindowLow;
	u64 uddProcessedByteCnt;

	u8 aucSaCipherKey[32];
	u8 aucSaAuthKey[128];
} __packed;

enum E_HAL_SEC_IPSEC_CIPHER_ALG {
	e_HAL_IPSEC_CIPHER_NULL = 0x00,
	e_HAL_IPSEC_CIPHER_AES_CTR = 0x11,
	e_HAL_IPSEC_CIPHER_AES_CBC = 0x12,
	e_HAL_IPSEC_CIPHER_AES_ECB = 0x13,
	e_HAL_IPSEC_CIPHER_AES_GCM = 0x14,
	e_HAL_IPSEC_CIPHER_AES_CCM = 0x15,
	e_HAL_IPSEC_CIPHER_AES_GMAC = 0x16,

	e_HAL_IPSEC_CIPHER_SM4_CTR = 0x17,
	e_HAL_IPSEC_CIPHER_SM4_CBC = 0x18,
	e_HAL_IPSEC_CIPHER_SM4_ECB = 0x19,

	e_HAL_IPSEC_CIPHER_AES_XTS = 0x1a,
	e_HAL_IPSEC_CIPHER_SM4_XTS = 0x1b,

	e_HAL_IPSEC_CIPHER_DES_CBC = 0x31,
	e_HAL_IPSEC_CIPHER_3DES_CBC = 0x32,
	e_HAL_IPSEC_CIPHER_CHACHA = 0x50,
};

enum E_HAL_SEC_IPSEC_AUTH_ALG {
	e_HAL_IPSEC_AUTH_NULL = 0x00,

	e_HAL_IPSEC_AUTH_AES_GMAC = 0x16, /* 1 */
	e_HAL_IPSEC_AUTH_SM4_GMAC = 0x1e,

	e_HAL_IPSEC_AUTH_AES_CMAC32 = 0x22, /* 3 */
	e_HAL_IPSEC_AUTH_AES_CMAC96 = 0x23,
	e_HAL_IPSEC_AUTH_AES_XCBCMAC = 0x21,
	e_HAL_IPSEC_AUTH_AES_SHA1 = 0x41, /* 6 */
	e_HAL_IPSEC_AUTH_AES_SHA224 = 0x42,
	e_HAL_IPSEC_AUTH_AES_SHA256 = 0x44,
	e_HAL_IPSEC_AUTH_AES_SHA384 = 0x45,
	e_HAL_IPSEC_AUTH_AES_SHA512 = 0x46,
	e_HAL_IPSEC_AUTH_AES_MD5 = 0x43,
	e_HAL_IPSEC_AUTH_SM3 = 0x47,
};

struct T_ZXDH_EALGO {
	char alg_name[64];
	char compat_name[64];
	enum E_HAL_SEC_IPSEC_CIPHER_ALG e_zxdh_ealgo_id;
};

struct T_ZXDH_ALGO {
	char alg_name[64];
	char compat_name[64];
	enum E_HAL_SEC_IPSEC_AUTH_ALG e_zxdh_auth_id;
};

void BttlPubDump(unsigned char *ucBuf, u32 udLen);
u32 CmdkBttlTestSecDtbSaAdd(struct zxdh_en_device *en_dev,
			    enum E_CMDK_DTB_SA_CMD_TYPE eDtbSaCmdType, enum E_SA_TYPE eSaType,
			    u64 uddSaVirAddr, u32 udDtbSaIsIntEn, u32 udDtbLen, u32 udQueIndex);
void zxdh_ipsec_del_sa(struct xfrm_state *xs);
bool zxdh_ipsec_offload_ok(struct sk_buff *skb, struct xfrm_state *xs);
void zxdh_ipsec_state_advance_esn(struct xfrm_state *x);
void zxdh_ipsec_state_update_curlft(struct xfrm_state *x);
int zxdh_ipsec_policy_add(struct xfrm_policy *x);
void zxdh_ipsec_policy_delete(struct xfrm_policy *x);
void zxdh_ipsec_policy_free(struct xfrm_policy *x);

#endif
