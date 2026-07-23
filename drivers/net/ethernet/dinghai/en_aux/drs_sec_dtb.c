// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/dcache.h>
#include <linux/mm.h>
#include <linux/memory.h>
#include <linux/init.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/stat.h>
#include <linux/kernel.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/delay.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>

#include <linux/netdevice.h>
#include <linux/pfkeyv2.h>
#include <net/xfrm.h>
#include "driver.h"
#include "../en_aux.h"
#include "drs_sec_dtb.h"

u32 g_udDownloadSaNum = 1;
u32 gudTunnelID;
u32 gudDtbSaNum = 1;
enum E_INLINE_TYPE e_gInlineType;
u64 guddAntiWindow = 2047;

u64 guddSecTestSaDtbPdVirAddr;

u32 gudSecTestSwanSrcIp = 0x0A04B007;
u32 gudSecTestSwanDstIp = 0x0AE3656D;

u8 gudIpType = 1;

u16 gusOutSaOffset;
u32 gudOutSaId;

u64 HalBttlSecRegBaseGet(struct zxdh_en_device *en_dev)
{
	if (en_dev == NULL) {
		DH_LOG_INFO(MODULE_SEC, "Null Ptr Err! Fuc:%s,Line:%d,File:%s\n", __func__,
			    __LINE__, __FILE__);
		return PUB_ERROR;
	}
	return en_dev->ops->get_bar_virt_addr(en_dev->parent, 0) + 0x7000;
}

static int zxdh_ipsec_cipher_id_get(u8 ealgo, char *p_alg_name, char *p_aead_name,
				    enum E_HAL_SEC_IPSEC_CIPHER_ALG *p_zxdh_ealgo_id)
{
	int i = 0;
	struct T_ZXDH_EALGO atZxdhEalgo[] = {
		{ "rfc7539esp(chacha20,poly1305)", "", e_HAL_IPSEC_CIPHER_CHACHA },
	};

	if ((!p_alg_name) || (!p_aead_name))
		return -1;
	for (i = 0; i < sizeof(atZxdhEalgo) / sizeof(struct T_ZXDH_EALGO); i++) {
		if ((strcmp(p_alg_name, atZxdhEalgo[i].alg_name) == 0) ||
		    (strcmp(p_alg_name, atZxdhEalgo[i].compat_name) == 0)) {
			*p_zxdh_ealgo_id = atZxdhEalgo[i].e_zxdh_ealgo_id;
			return 0;
		}
		if ((strcmp(p_aead_name, atZxdhEalgo[i].alg_name) == 0) ||
		    (strcmp(p_aead_name, atZxdhEalgo[i].compat_name) == 0)) {
			*p_zxdh_ealgo_id = atZxdhEalgo[i].e_zxdh_ealgo_id;
			return 0;
		}
	}

	switch (ealgo) {
	case SADB_EALG_NULL:
	case SADB_EALG_NONE:
		*p_zxdh_ealgo_id = e_HAL_IPSEC_CIPHER_NULL;
		break;
	case SADB_EALG_DESCBC:
		*p_zxdh_ealgo_id = e_HAL_IPSEC_CIPHER_DES_CBC;
		break;
	case SADB_EALG_3DESCBC:
		*p_zxdh_ealgo_id = e_HAL_IPSEC_CIPHER_3DES_CBC;
		break;
	case SADB_X_EALG_AESCBC:
		*p_zxdh_ealgo_id = e_HAL_IPSEC_CIPHER_AES_CBC;
		break;
	case SADB_X_EALG_AESCTR:
		*p_zxdh_ealgo_id = e_HAL_IPSEC_CIPHER_AES_CTR;
		break;
	case SADB_X_EALG_AES_CCM_ICV8:
		*p_zxdh_ealgo_id = e_HAL_IPSEC_CIPHER_AES_CCM;
		break;
	case SADB_X_EALG_AES_CCM_ICV12:
		*p_zxdh_ealgo_id = e_HAL_IPSEC_CIPHER_AES_CCM;
		break;
	case SADB_X_EALG_AES_CCM_ICV16:
		*p_zxdh_ealgo_id = e_HAL_IPSEC_CIPHER_AES_CCM;
		break;
	case SADB_X_EALG_AES_GCM_ICV8:
		*p_zxdh_ealgo_id = e_HAL_IPSEC_CIPHER_AES_GCM;
		break;
	case SADB_X_EALG_AES_GCM_ICV12:
		*p_zxdh_ealgo_id = e_HAL_IPSEC_CIPHER_AES_GCM;
		break;
	case SADB_X_EALG_AES_GCM_ICV16:
		*p_zxdh_ealgo_id = e_HAL_IPSEC_CIPHER_AES_GCM;
		break;
	case SADB_X_EALG_NULL_AES_GMAC:
		*p_zxdh_ealgo_id = e_HAL_IPSEC_CIPHER_AES_GMAC;
		break;
	default:
		return -1;
	}

	return 0;
}

static int zxdh_ipsec_auth_id_get(u8 aalgo, char *p_alg_name,
				  enum E_HAL_SEC_IPSEC_AUTH_ALG *p_zxdh_auth_id)
{
	int i = 0;
	struct T_ZXDH_ALGO atZxdhAlgo[] = {
		{ "cmac(aes)", "", e_HAL_IPSEC_AUTH_AES_CMAC32 },
	};

	if (!p_alg_name)
		return -1;
	for (i = 0; i < sizeof(atZxdhAlgo) / sizeof(struct T_ZXDH_ALGO); i++) {
		DH_LOG_INFO(MODULE_SEC, "%s\n", p_alg_name);
		DH_LOG_INFO(MODULE_SEC, "%s\n", atZxdhAlgo[i].alg_name);
		if ((strcmp(p_alg_name, atZxdhAlgo[i].alg_name) == 0) ||
		    (strcmp(p_alg_name, atZxdhAlgo[i].compat_name) == 0)) {
			*p_zxdh_auth_id = atZxdhAlgo[i].e_zxdh_auth_id;
			return 0;
		}
	}

	switch (aalgo) {
	case SADB_X_AALG_NULL:
	case SADB_AALG_NONE:
		*p_zxdh_auth_id = e_HAL_IPSEC_AUTH_NULL;
		break;
	case SADB_AALG_MD5HMAC:
		*p_zxdh_auth_id = e_HAL_IPSEC_AUTH_AES_MD5;
		break;
	case SADB_AALG_SHA1HMAC:
		*p_zxdh_auth_id = e_HAL_IPSEC_AUTH_AES_SHA1;
		break;
	case SADB_X_AALG_SHA2_256HMAC:
		*p_zxdh_auth_id = e_HAL_IPSEC_AUTH_AES_SHA256;
		break;
	case SADB_X_AALG_SHA2_384HMAC:
		*p_zxdh_auth_id = e_HAL_IPSEC_AUTH_AES_SHA384;
		break;
	case SADB_X_AALG_SHA2_512HMAC:
		*p_zxdh_auth_id = e_HAL_IPSEC_AUTH_AES_SHA512;
		break;
	case SADB_X_AALG_AES_XCBC_MAC:
		*p_zxdh_auth_id = e_HAL_IPSEC_AUTH_AES_XCBCMAC;
		break;
	default:
		return -1;
	}

	return 0;
}

u32 CmdkBttlSecSaParamConstruct(u32 udEntryValid, enum E_CMDK_SEC_IPSEC_MODE eTunnelMode,
				u32 udSeqCnterOverflow, enum E_CMDK_LIVETIME_TYPES eLiveTimeType,
				enum E_CMDK_SEC_SA_DF_MODE eSaDfMode,
				enum E_CMDK_SEC_ENCRYP_MODE eEncryptionMode, u32 udIcvLen,
				u16 *pusSaParam)
{
	u32 udIcvLenNew = udIcvLen / 4;

	if (((BITWIDTH1 + 1) <= (udEntryValid)) || e_SEC_IPSEC_MODE_LAST <= eTunnelMode ||
	    ((BITWIDTH1 + 1) <= udSeqCnterOverflow) ||
	    e_SEC_SA_LIVETIME_TYPE_LAST <= eLiveTimeType || e_SEC_SA_DF_MODE_LAST <= eSaDfMode ||
	    e_SEC_ENCRYP_MODE_LAST <= eEncryptionMode || ((BITWIDTH6 + 1) <= udIcvLenNew))
		return 1;

	*pusSaParam = udIcvLenNew | (eEncryptionMode << 6) | (eSaDfMode << 9) |
		      (eLiveTimeType << 11) | (udSeqCnterOverflow << 13) | (eTunnelMode << 14) |
		      (udEntryValid << 15);

	return 0;
}

static int zxdh_ipsec_dtb_out_sa_get(struct xfrm_state *xs, struct T_HAL_SA_DTB_HW_OUT *ptDtbOutSa)
{
	int err = -EINVAL;
	u16 usSaParam = 0;
	u32 udIcvLen = 0;
	enum E_HAL_SEC_IPSEC_AUTH_ALG zxdh_auth_id;
	enum E_HAL_SEC_IPSEC_CIPHER_ALG zxdh_ealgo_id;
	enum E_CMDK_SEC_ENCRYP_MODE zxdh_encpy_mode = e_SEC_ENCRYP_MODE_LAST;
	char test_alg_name[] = "zxdh_alg_test";
	char *p_aalg_alg_name = test_alg_name;
	char *p_ealg_alg_name = test_alg_name;
	char *p_aead_alg_name = test_alg_name;

	if (xs->aalg)
		p_aalg_alg_name = xs->aalg->alg_name;
	if (xs->ealg)
		p_ealg_alg_name = xs->ealg->alg_name;
	if (xs->aead)
		p_aead_alg_name = xs->aead->alg_name;

	//DH_LOG_INFO(MODULE_SEC, "xs:0x%llx\n",xs);
	//DH_LOG_INFO(MODULE_SEC, "ptDtbOutSa:0x%llx\n",ptDtbOutSa);

	err = zxdh_ipsec_auth_id_get(xs->props.aalgo, p_aalg_alg_name, &zxdh_auth_id);
	if (err) {
		DH_LOG_INFO(MODULE_SEC, "Cannot offload xfrm state aalgo:%u\n", xs->props.aalgo);
		return -EINVAL;
	}
	err = zxdh_ipsec_cipher_id_get(xs->props.ealgo, p_ealg_alg_name, p_aead_alg_name,
				       &zxdh_ealgo_id);
	if (err) {
		DH_LOG_INFO(MODULE_SEC, "Cannot offload xfrm state ealgo:%u\n", xs->props.aalgo);
		return -EINVAL;
	}

	//DH_LOG_INFO(MODULE_SEC, "replay_esn 0x%llx\n",xs->replay_esn);
	ptDtbOutSa->ucAuthkeyLen = 0;

	if (zxdh_auth_id == e_HAL_IPSEC_AUTH_NULL) {
		zxdh_encpy_mode = e_SEC_ENCRYP_ESP_ENCRYP_MODE;
	} else {
		ptDtbOutSa->ucAuthkeyLen = (xs->aalg->alg_key_len + 7) / 8;
		udIcvLen = (xs->aalg->alg_trunc_len + 7) / 8;
		memcpy((ptDtbOutSa->aucSaAuthKey), xs->aalg->alg_key, ptDtbOutSa->ucAuthkeyLen);
	}

	if ((zxdh_ealgo_id != e_HAL_IPSEC_CIPHER_NULL) && (zxdh_auth_id != e_HAL_IPSEC_AUTH_NULL))
		zxdh_encpy_mode = e_SEC_ENCRYP_ESP_AUTH_AND_ESP_ENCRYP_MODE;

	if ((zxdh_ealgo_id == e_HAL_IPSEC_CIPHER_AES_GCM) ||
	    (zxdh_ealgo_id == e_HAL_IPSEC_CIPHER_CHACHA) ||
	    (zxdh_ealgo_id == e_HAL_IPSEC_CIPHER_AES_GMAC)) {
		zxdh_encpy_mode = e_SEC_ENCRYP_ESP_COMBINED_MODE;

		ptDtbOutSa->ucCipherkeyLen = (xs->aead->alg_key_len + 7) / 8 - 4;
		udIcvLen = (xs->aead->alg_icv_len + 7) / 8;
		memcpy(&(ptDtbOutSa->udSalt), xs->aead->alg_key + ptDtbOutSa->ucCipherkeyLen,
		       sizeof(ptDtbOutSa->udSalt));
		memcpy((ptDtbOutSa->aucSaCipherKey), xs->aead->alg_key, ptDtbOutSa->ucCipherkeyLen);
	}

	else if (zxdh_ealgo_id == e_HAL_IPSEC_CIPHER_AES_CCM) {
		zxdh_encpy_mode = e_SEC_ENCRYP_ESP_COMBINED_MODE;

		ptDtbOutSa->ucCipherkeyLen = (xs->aead->alg_key_len + 7) / 8 - 3;
		udIcvLen = (xs->aead->alg_icv_len + 7) / 8;
		memcpy(&(ptDtbOutSa->udSalt), xs->aead->alg_key + ptDtbOutSa->ucCipherkeyLen,
		       sizeof(ptDtbOutSa->udSalt));
		memcpy((ptDtbOutSa->aucSaCipherKey), xs->aead->alg_key, ptDtbOutSa->ucCipherkeyLen);
	}

	else if (zxdh_ealgo_id == e_HAL_IPSEC_CIPHER_AES_CTR) {
		ptDtbOutSa->ucCipherkeyLen = (xs->ealg->alg_key_len + 7) / 8 - 4;
		memcpy(&(ptDtbOutSa->udSalt), xs->ealg->alg_key + ptDtbOutSa->ucCipherkeyLen,
		       sizeof(ptDtbOutSa->udSalt));
		memcpy((ptDtbOutSa->aucSaCipherKey), xs->ealg->alg_key, ptDtbOutSa->ucCipherkeyLen);
	}

	else if (zxdh_ealgo_id == e_HAL_IPSEC_CIPHER_NULL) {
		zxdh_encpy_mode = e_SEC_ENCRYP_ESP_AUTH_MODE;
		ptDtbOutSa->ucCipherkeyLen = 0;
	} else {
		ptDtbOutSa->ucCipherkeyLen = (xs->ealg->alg_key_len + 7) / 8;
		memcpy((ptDtbOutSa->aucSaCipherKey), xs->ealg->alg_key, ptDtbOutSa->ucCipherkeyLen);
	}

	ptDtbOutSa->udSN = xs->replay.oseq;
	ptDtbOutSa->uddProcessedByteCnt = xs->curlft.bytes;

	ptDtbOutSa->udSPI = xs->id.spi;
	ptDtbOutSa->udSaId = PUB_HTON32(0x80001);

	ptDtbOutSa->ucCiperID = zxdh_ealgo_id;
	ptDtbOutSa->ucAuthID = zxdh_auth_id;

	CmdkBttlSecSaParamConstruct(1, xs->props.mode, 0, e_SEC_SA_LIVETIME_TIME_TYPE,
				    e_SEC_SA_DF_BYPASS_MODE, zxdh_encpy_mode, udIcvLen, &usSaParam);
	ptDtbOutSa->usSaParam = PUB_HTON16(usSaParam);

	ptDtbOutSa->usFrag_State = PUB_HTON16(0xd2c8);

	ptDtbOutSa->udLifetimeSecMax = PUB_HTON32(0xc4454766);
	ptDtbOutSa->uddLifetimByteCntMax = PUB_HTON64(0xffffffffffffffff);

	ptDtbOutSa->ucProtocol = xs->id.proto;
	ptDtbOutSa->ucTOS = 0xbb;

	ptDtbOutSa->ucEsnFlag = 0;
	if (xs->props.flags & XFRM_STATE_ESN) {
		if (!xs->replay_esn)
			return 1;
		ptDtbOutSa->ucEsnFlag = 0xff;
		ptDtbOutSa->udSN = xs->replay_esn->oseq;
		ptDtbOutSa->udESN = xs->replay_esn->oseq_hi;
	}

	/*ipv4*/
	if (xs->props.family == AF_INET) {
		ptDtbOutSa->ucIpType = 1 << 6;
		ptDtbOutSa->udSrcAddress0 = xs->props.saddr.a4;
		ptDtbOutSa->udSrcAddress1 = 0x0;
		ptDtbOutSa->udSrcAddress2 = 0x0;
		ptDtbOutSa->udSrcAddress3 = 0x0;

		ptDtbOutSa->udDstAddress0 = xs->id.daddr.a4;
		ptDtbOutSa->udDstAddress1 = 0x0;
		ptDtbOutSa->udDstAddress2 = 0x0;
		ptDtbOutSa->udDstAddress3 = 0x0;
	}
	/*ipv4*/
	else if (xs->props.family == AF_INET6) {
		ptDtbOutSa->ucIpType = 2 << 6;
		ptDtbOutSa->udSrcAddress0 = xs->props.saddr.a6[0];
		ptDtbOutSa->udSrcAddress1 = xs->props.saddr.a6[1];
		ptDtbOutSa->udSrcAddress2 = xs->props.saddr.a6[2];
		ptDtbOutSa->udSrcAddress3 = xs->props.saddr.a6[3];

		ptDtbOutSa->udDstAddress0 = xs->id.daddr.a6[0];
		ptDtbOutSa->udDstAddress1 = xs->id.daddr.a6[1];
		ptDtbOutSa->udDstAddress2 = xs->id.daddr.a6[2];
		ptDtbOutSa->udDstAddress3 = xs->id.daddr.a6[3];
	} else {
		return -EINVAL;
	}

	ptDtbOutSa->udRSV0 = 0x0;
	ptDtbOutSa->udRSV1 = 0x0;
	ptDtbOutSa->udRSV2 = 0x0;

	DH_LOG_INFO(MODULE_SEC, "ptDtbOutSa->ucAuthkeyLen:0x%x\n", ptDtbOutSa->ucAuthkeyLen);
	DH_LOG_INFO(MODULE_SEC, "ptDtbOutSa->ucCipherkeyLen:0x%x\n", ptDtbOutSa->ucCipherkeyLen);
	DH_LOG_INFO(MODULE_SEC, "zxdh_encpy_mode:0x%x\n", zxdh_encpy_mode);
	DH_LOG_INFO(MODULE_SEC, "ptDtbOutSa->ucCiperID:0x%x\n", ptDtbOutSa->ucCiperID);
	DH_LOG_INFO(MODULE_SEC, "ptDtbOutSa->ucAuthID:0x%x\n", ptDtbOutSa->ucAuthID);

	return 0;
}

static int zxdh_ipsec_dtb_in_sa_get(struct xfrm_state *xs, struct T_HAL_SA_DTB_HW_IN *ptDtbInSa)
{
	int err = -EINVAL;
	u16 usSaParam = 0;
	u32 udIcvLen = 0;
	enum E_HAL_SEC_IPSEC_AUTH_ALG zxdh_auth_id;
	enum E_HAL_SEC_IPSEC_CIPHER_ALG zxdh_ealgo_id;
	enum E_CMDK_SEC_ENCRYP_MODE zxdh_encpy_mode = e_SEC_ENCRYP_MODE_LAST;
	char test_alg_name[] = "zxdh_alg_test";
	char *p_aalg_alg_name = test_alg_name;
	char *p_ealg_alg_name = test_alg_name;
	char *p_aead_alg_name = test_alg_name;

	if (xs->aalg)
		p_aalg_alg_name = xs->aalg->alg_name;
	if (xs->ealg)
		p_ealg_alg_name = xs->ealg->alg_name;
	if (xs->aead)
		p_aead_alg_name = xs->aead->alg_name;
	err = zxdh_ipsec_auth_id_get(xs->props.aalgo, p_aalg_alg_name, &zxdh_auth_id);
	if (err) {
		DH_LOG_INFO(MODULE_SEC, "Cannot offload xfrm state aalgo:%u\n", xs->props.aalgo);
		return -EINVAL;
	}
	err = zxdh_ipsec_cipher_id_get(xs->props.ealgo, p_ealg_alg_name, p_aead_alg_name,
				       &zxdh_ealgo_id);
	if (err) {
		DH_LOG_INFO(MODULE_SEC, "Cannot offload xfrm state ealgo:%u\n", xs->props.aalgo);
		return -EINVAL;
	}

	ptDtbInSa->ucAuthkeyLen = 0;

	if (zxdh_auth_id == e_HAL_IPSEC_AUTH_NULL) {
		zxdh_encpy_mode = e_SEC_ENCRYP_ESP_ENCRYP_MODE;
	} else {
		ptDtbInSa->ucAuthkeyLen = (xs->aalg->alg_key_len + 7) / 8;
		udIcvLen = (xs->aalg->alg_trunc_len + 7) / 8;
		memcpy((ptDtbInSa->aucSaAuthKey), xs->aalg->alg_key, ptDtbInSa->ucAuthkeyLen);
	}

	if ((zxdh_ealgo_id != e_HAL_IPSEC_CIPHER_NULL) && (zxdh_auth_id != e_HAL_IPSEC_AUTH_NULL))
		zxdh_encpy_mode = e_SEC_ENCRYP_ESP_AUTH_AND_ESP_ENCRYP_MODE;

	if ((zxdh_ealgo_id == e_HAL_IPSEC_CIPHER_AES_GCM) ||
	    (zxdh_ealgo_id == e_HAL_IPSEC_CIPHER_CHACHA) ||
	    (zxdh_ealgo_id == e_HAL_IPSEC_CIPHER_AES_GMAC)) {
		zxdh_encpy_mode = e_SEC_ENCRYP_ESP_COMBINED_MODE;

		ptDtbInSa->ucCipherkeyLen = (xs->aead->alg_key_len + 7) / 8 - 4;
		udIcvLen = (xs->aead->alg_icv_len + 7) / 8;
		memcpy(&(ptDtbInSa->udSalt), xs->aead->alg_key + ptDtbInSa->ucCipherkeyLen,
		       sizeof(ptDtbInSa->udSalt));
		memcpy((ptDtbInSa->aucSaCipherKey), xs->aead->alg_key, ptDtbInSa->ucCipherkeyLen);
	}

	else if (zxdh_ealgo_id == e_HAL_IPSEC_CIPHER_AES_CCM) {
		zxdh_encpy_mode = e_SEC_ENCRYP_ESP_COMBINED_MODE;

		ptDtbInSa->ucCipherkeyLen = (xs->aead->alg_key_len + 7) / 8 - 3;
		udIcvLen = (xs->aead->alg_icv_len + 7) / 8;
		memcpy(&(ptDtbInSa->udSalt), xs->aead->alg_key + ptDtbInSa->ucCipherkeyLen,
		       sizeof(ptDtbInSa->udSalt));
		memcpy((ptDtbInSa->aucSaCipherKey), xs->aead->alg_key, ptDtbInSa->ucCipherkeyLen);
	}

	else if (zxdh_ealgo_id == e_HAL_IPSEC_CIPHER_AES_CTR) {
		ptDtbInSa->ucCipherkeyLen = (xs->ealg->alg_key_len + 7) / 8 - 4;
		memcpy(&(ptDtbInSa->udSalt), xs->ealg->alg_key + ptDtbInSa->ucCipherkeyLen,
		       sizeof(ptDtbInSa->udSalt));
		memcpy((ptDtbInSa->aucSaCipherKey), xs->ealg->alg_key, ptDtbInSa->ucCipherkeyLen);
	}

	else if (zxdh_ealgo_id == e_HAL_IPSEC_CIPHER_NULL) {
		zxdh_encpy_mode = e_SEC_ENCRYP_ESP_AUTH_MODE;
		ptDtbInSa->ucCipherkeyLen = 0;
	} else {
		ptDtbInSa->ucCipherkeyLen = (xs->ealg->alg_key_len + 7) / 8;
		memcpy((ptDtbInSa->aucSaCipherKey), xs->ealg->alg_key, ptDtbInSa->ucCipherkeyLen);
	}

	ptDtbInSa->uddProcessedByteCnt = xs->curlft.bytes;

	ptDtbInSa->udSPI = xs->id.spi;
	ptDtbInSa->udSaId = PUB_HTON32(0x80000);

	ptDtbInSa->ucCiperID = zxdh_ealgo_id;
	ptDtbInSa->ucAuthID = zxdh_auth_id;

	CmdkBttlSecSaParamConstruct(1, xs->props.mode, 0, e_SEC_SA_LIVETIME_TIME_TYPE,
				    e_SEC_SA_DF_BYPASS_MODE, zxdh_encpy_mode, udIcvLen, &usSaParam);
	ptDtbInSa->usSaParam = PUB_HTON16(usSaParam);

	ptDtbInSa->usFrag_State = PUB_HTON16(0xd2c8);

	ptDtbInSa->udLifetimeSecMax = PUB_HTON32(0xc4454766);
	ptDtbInSa->uddLifetimByteCntMax = PUB_HTON64(0xffffffffffffffff);

	ptDtbInSa->ucProtocol = xs->id.proto;
	ptDtbInSa->ucTOS = 0xbb;

	ptDtbInSa->ucEsnFlag = 0;
	if (xs->props.flags & XFRM_STATE_ESN) {
		if (!xs->replay_esn)
			return 1;
		ptDtbInSa->ucEsnFlag = 0xff;
		ptDtbInSa->udAntiWindowHigh = PUB_HTON32(xs->replay_esn->seq_hi); /*ESN*/
		ptDtbInSa->udAntiWindowLow = PUB_HTON32(xs->replay_esn->replay_window - 1);
		memcpy((void *)ptDtbInSa->aucBitmap, (void *)xs->replay_esn->bmp,
		       xs->replay_esn->bmp_len * sizeof(__u32));
	}

	/*ipv4*/
	if (xs->props.family == AF_INET) {
		ptDtbInSa->ucIpType = 1 << 6;
		ptDtbInSa->udSrcAddress0 = xs->props.saddr.a4;
		ptDtbInSa->udSrcAddress1 = 0x0;
		ptDtbInSa->udSrcAddress2 = 0x0;
		ptDtbInSa->udSrcAddress3 = 0x0;

		ptDtbInSa->udDstAddress0 = xs->id.daddr.a4;
		ptDtbInSa->udDstAddress1 = 0x0;
		ptDtbInSa->udDstAddress2 = 0x0;
		ptDtbInSa->udDstAddress3 = 0x0;
	}
	/*ipv4*/
	else if (xs->props.family == AF_INET6) {
		ptDtbInSa->ucIpType = 2 << 6;
		ptDtbInSa->udSrcAddress0 = xs->props.saddr.a6[0];
		ptDtbInSa->udSrcAddress1 = xs->props.saddr.a6[1];
		ptDtbInSa->udSrcAddress2 = xs->props.saddr.a6[2];
		ptDtbInSa->udSrcAddress3 = xs->props.saddr.a6[3];

		ptDtbInSa->udDstAddress0 = xs->id.daddr.a6[0];
		ptDtbInSa->udDstAddress1 = xs->id.daddr.a6[1];
		ptDtbInSa->udDstAddress2 = xs->id.daddr.a6[2];
		ptDtbInSa->udDstAddress3 = xs->id.daddr.a6[3];
	} else {
		return -EINVAL;
	}

	ptDtbInSa->udOutSaId = 0x0;
	ptDtbInSa->usOutSaOffset = 0x0;

	ptDtbInSa->udRSV0 = 0x0;
	ptDtbInSa->udRSV1 = 0x0;

	DH_LOG_INFO(MODULE_SEC, "ptDtbInSa->ucAuthkeyLen:0x%x\n", ptDtbInSa->ucAuthkeyLen);
	DH_LOG_INFO(MODULE_SEC, "ptDtbInSa->ucCipherkeyLen:0x%x\n", ptDtbInSa->ucCipherkeyLen);
	DH_LOG_INFO(MODULE_SEC, "zxdh_encpy_mode:0x%x\n", zxdh_encpy_mode);
	DH_LOG_INFO(MODULE_SEC, "ptDtbInSa->ucCiperID:0x%x\n", ptDtbInSa->ucCiperID);
	DH_LOG_INFO(MODULE_SEC, "ptDtbInSa->ucAuthID:0x%x\n", ptDtbInSa->ucAuthID);

	return 0;
}

void RdlSecWrite(u64 uddSecBase, u32 udRegOff, u32 udRegVal)
{
	PUB_WRITE_REG32(uddSecBase + udRegOff, udRegVal);
}

u32 HalSecWrite(struct zxdh_en_device *en_dev, u32 udSecEngineId, u32 udRegOff, u32 udRegVal)
{
	u64 uddBttlSecBase = 0;
	u32 udSecnBaseOff = 0;
	u64 uddSecnBase = 0;

	if (en_dev == NULL) {
		DH_LOG_INFO(MODULE_SEC, "Null Ptr Err! Fuc:%s,Line:%d,File:%s\n", __func__,
			    __LINE__, __FILE__);
		return PUB_ERROR;
	}

	uddBttlSecBase = HalBttlSecRegBaseGet(en_dev);

	uddSecnBase = uddBttlSecBase + udSecnBaseOff;
	RdlSecWrite(uddSecnBase, udRegOff, udRegVal);

	return 0;
}

u32 RdlSecRead(u64 uddSecBase, u32 udRegOff)
{
	return PUB_READ_REG32(uddSecBase + udRegOff);
}

u32 HalSecRead(struct zxdh_en_device *en_dev, u32 udSecEngineId, u32 udRegOff)
{
	u64 uddBttlSecBase = 0;
	u32 udSecnBaseOff = 0;
	u64 uddSecnBase = 0;

	if (en_dev == NULL) {
		DH_LOG_INFO(MODULE_SEC, "Null Ptr Err! Fuc:%s,Line:%d,File:%s\n", __func__,
			    __LINE__, __FILE__);
		return PUB_ERROR;
	}
	uddBttlSecBase = HalBttlSecRegBaseGet(en_dev);
	udSecnBaseOff = udSecEngineId * REG_SEC_IDX_OFFSET;
	uddSecnBase = uddBttlSecBase + udSecnBaseOff;

	return RdlSecRead(uddSecnBase, udRegOff);
}

u64 HalBttlVaToVpa(struct zxdh_en_device *en_dev, u64 pVaAddr)
{
	if (en_dev == NULL) {
		DH_LOG_INFO(MODULE_SEC, "Null Ptr Err! Fuc:%s,Line:%d,File:%s\n", __func__,
			    __LINE__, __FILE__);
		return PUB_ERROR;
	}
	return (u64)virt_to_phys((void *)pVaAddr);
}

u64 HalBttlVpaToVa(struct zxdh_en_device *en_dev, u64 pVpaAddr)
{
	if (en_dev == NULL) {
		DH_LOG_INFO(MODULE_SEC, "Null Ptr Err! Fuc:%s,Line:%d,File:%s\n", __func__,
			    __LINE__, __FILE__);
		return PUB_ERROR;
	}
	return (u64)phys_to_virt(pVpaAddr);
}

void BttlPubDump(unsigned char *ucBuf, u32 udLen)
{
	int i = 0;
	int j = 0;
	unsigned char *ptr = NULL;

	ptr = ucBuf;

	if (!ucBuf || udLen == 0)
		return;

	for (j = 0; j < 64; j++)
		pr_info("-");
	pr_info("\n");

	for (i = 0; i < udLen; i++) {
		if (i % 16 == 0)
			pr_info("0x%08x ", (i / 16) * 16);
		pr_info("%02X ", ptr[i]);
		if (i % 16 == 15) {
			pr_info("   *");
			pr_info("*\n");
		}
	}

	if (udLen % 16 == 0) {
		pr_info("\n");
	} else {
		for (i = (udLen % 16); i < 16; i++)
			pr_info("   ");
		pr_info("   *");
		pr_info("\n\n");
	}
}

u32 CmdkBttlTestSaAckRslGet(u64 uddSaVirAddr, enum E_CMDK_DTB_SA_CMD_TYPE eDtbSaCmdType,
			    u32 *pudIsDtbAckFinish, u32 *pudDtbAckRsl)
{
	u32 udVal = 0;
	u32 udDtbAckFinish = 0;

	*pudIsDtbAckFinish = 0;

	udVal = *((u32 *)(uddSaVirAddr));
	udDtbAckFinish = PUB_BIT_FIELD_RIGHT_JUST_GET64(udVal, 0, 24);
	*pudDtbAckRsl = PUB_BIT_FIELD_RIGHT_JUST_GET64(udVal, 24, 8);

	if (eDtbSaCmdType == E_DTB_SA_CMD_FLOW_DOWN) {
		if (udDtbAckFinish == 0x5a5a5a)
			*pudIsDtbAckFinish = 1;
	} else {
		if (udDtbAckFinish == 0x555555)
			*pudIsDtbAckFinish = 1;
	}

	return 0;
}

u32 CmdkBttlSecSaDownload(struct zxdh_en_device *en_dev, u32 udSecEngineId,
			  struct T_QUEUE_DTB_REG *pt, u32 udQueIndex)
{
	u32 udRet;
	u32 udRegVal;
	//u32 udQueIndex = 1;
	u32 udEpldVfunNum = 0;
	u32 udPcieDbiEn = 1;
	u32 udEpid = 5;
	u32 udVfuncNum = 0;
	u32 udCfgMsixVector = 2;
	u32 udFuncNum = 2;
	u32 udVfuncActive = 0;
	u16 usVport = 0;

	if (en_dev == NULL) {
		DH_LOG_INFO(MODULE_SEC, "Null Ptr Err! Fuc:%s,Line:%d,File:%s\n", __func__,
			    __LINE__, __FILE__);
		return PUB_ERROR;
	}
	usVport = en_dev->ops->get_vport(en_dev->parent);

	udEpid = EPID(usVport) + 5;
	udVfuncNum = VFUNC_NUM(usVport);
	udFuncNum = FUNC_NUM(usVport);
	udVfuncActive = VF_ACTIVE(usVport);

	DH_LOG_INFO(MODULE_SEC, "udEpid:0x%x,udVfuncNum:0x%x\n", udEpid, udVfuncNum);
	DH_LOG_INFO(MODULE_SEC, "udFuncNum:0x%x,udVfuncActive:0x%x\n", udFuncNum, udVfuncActive);

	PUB_BIT_FIELD_SET64(udEpldVfunNum, udVfuncActive, 0, 1);
	PUB_BIT_FIELD_SET64(udEpldVfunNum, udFuncNum, 5, 3);
	PUB_BIT_FIELD_SET64(udEpldVfunNum, udCfgMsixVector, 8, 7);
	PUB_BIT_FIELD_SET64(udEpldVfunNum, udVfuncNum, 16, 8);
	PUB_BIT_FIELD_SET64(udEpldVfunNum, udEpid, 24, 4);
	PUB_BIT_FIELD_SET64(udEpldVfunNum, udPcieDbiEn, 31, 1);

	//return 0;
	DH_LOG_INFO(MODULE_SEC, "udEpldVfunNum = 0x%x\n", udEpldVfunNum);
	HalSecWrite(en_dev, udSecEngineId, REG_SEC_CFG_EPID_V_FUNC_NUM_0_127(udQueIndex),
		    udEpldVfunNum);

	udRegVal = HalSecRead(en_dev, udSecEngineId,
			      REG_SEC_INFO_QUEUE_BUF_SPACE_LEFT_0_127(udQueIndex));
	if (udRegVal < 2) {
		BTTL_PRINTF("queue:%u buf empty left:%u\n", udQueIndex, udRegVal);
		return 1;
	}
	if (udRegVal > 0x20) {
		BTTL_PRINTF("queue:%u buf left:%u\n", udQueIndex, udRegVal);
		return 1;
	}

	udRet = HalSecWrite(en_dev, udSecEngineId, REG_SEC_CFG_QUEUE_DTB_ADDR_H_0_127(udQueIndex),
			    pt->DtbAddrH);
	udRet = HalSecWrite(en_dev, udSecEngineId, REG_SEC_CFG_QUEUE_DTB_ADDR_L_0_127(udQueIndex),
			    pt->DtbAddrL);
	udRet = HalSecWrite(en_dev, udSecEngineId, REG_SEC_CFG_QUEUE_DTB_LEN_0_127(udQueIndex),
			    pt->DtbCmd);

	return 0;
}

u32 gudTestCnt;
u32 CmdkBttlTestSecDtbSaAdd(struct zxdh_en_device *en_dev,
			    enum E_CMDK_DTB_SA_CMD_TYPE eDtbSaCmdType, enum E_SA_TYPE eSaType,
			    u64 uddSaVirAddr, u32 udDtbSaIsIntEn, u32 udDtbLen, u32 udQueIndex)
{
	struct T_QUEUE_DTB_REG tDtbReg = { 0 };
	u32 udDtbCmd = 0;
	u64 uddSaPhaAddr = 0;
	u32 udIsDtbAckFinish = 0;
	u32 udDtbAckRsl = 0;
	u32 udRet = 0;
	int i = 0;

	if (en_dev == NULL) {
		DH_LOG_INFO(MODULE_SEC, "Null Ptr Err! Fuc:%s,Line:%d,File:%s\n", __func__,
			    __LINE__, __FILE__);
		return PUB_ERROR;
	}

	uddSaPhaAddr = (u64)HalBttlVaToVpa(en_dev, uddSaVirAddr);
	DH_LOG_INFO(MODULE_SEC, "uddSaVirAddr:0x%llx,uddSaPhaAddr:0x%llx\n", uddSaVirAddr,
		    uddSaPhaAddr);

	PUB_BIT_FIELD_SET64(udDtbCmd, udDtbLen >> 4, 0, 10);
	PUB_BIT_FIELD_SET64(udDtbCmd, eSaType, 27, 2);
	PUB_BIT_FIELD_SET64(udDtbCmd, udDtbSaIsIntEn, 29, 1);
	PUB_BIT_FIELD_SET64(udDtbCmd, eDtbSaCmdType, 30, 1);

	tDtbReg.DtbAddrH = (u32)PUB_BIT_FIELD_RIGHT_JUST_GET64(uddSaPhaAddr, 32, 32);
	tDtbReg.DtbAddrL = (u32)PUB_BIT_FIELD_RIGHT_JUST_GET64(uddSaPhaAddr, 0, 32);
	tDtbReg.DtbCmd = udDtbCmd;

	for (i = 0; i < gudDtbSaNum; i++)
		udRet = CmdkBttlSecSaDownload(en_dev, 0, &tDtbReg, udQueIndex);

	msleep(1000);

	udRet = CmdkBttlTestSaAckRslGet(uddSaVirAddr, eDtbSaCmdType, &udIsDtbAckFinish,
					&udDtbAckRsl);

	if (udRet != PUB_OK) {
		DH_LOG_INFO(MODULE_SEC, "%s Error,Line:%d,Ret:0x%x\n", __func__, __LINE__, udRet);
		return udRet;
	}

	if ((udIsDtbAckFinish == 1) && (udDtbAckRsl == 0xff))
		return 0;

	BTTL_PRINTF("CmdkBttlTestSa Dtb Ack is error!! udIsDtbAckFinish:%u,udDtbAckRsl:%u\n",
		    udIsDtbAckFinish, udDtbAckRsl);
	BttlPubDump((unsigned char *)uddSaVirAddr, 0x60);
	return 1;
}

static int zxdh_ipsec_add_sa(struct xfrm_state *xs, __maybe_unused struct netlink_ext_ack *extack)
{
	struct xfrm_dev_offload *xso = &xs->xso;
	struct net_device *netdev = xso->dev;
	struct zxdh_en_priv *en_priv = NULL;
	//struct zxdh_en_device *en_dev = NULL;
	struct zxdh_en_device *en_dev = NULL;
	dma_addr_t dma_handle;
	u32 dma_size = 0x1000;

	u64 uddDtbSaVirAddr = 0;
	u32 udSaTblLen = 0;
	int ret = 0;

	en_priv = netdev_priv(netdev);
	en_dev = &(en_priv->edev);

	if (unlikely(en_dev->drs_sec_pri.SecVAddr == 0)) {
		en_dev->drs_sec_pri.SecVAddr = (u64)dma_alloc_coherent(
			en_dev->dmadev, dma_size, &dma_handle, GFP_KERNEL);
		if (en_dev->drs_sec_pri.SecVAddr == 0) {
			DH_LOG_INFO(MODULE_SEC, "zxdh ipsec add sa dma_alloc_coherent fail\n");
			return -1;
		}
		en_dev->drs_sec_pri.SecPAddr = dma_handle;
		en_dev->drs_sec_pri.SecMemSize = dma_size;
	}
	uddDtbSaVirAddr = en_dev->drs_sec_pri.SecVAddr;

	DH_LOG_INFO(MODULE_SEC, "uddDtbSaVirAddr:0x%llx\n", uddDtbSaVirAddr);
	//DH_LOG_INFO(MODULE_SEC, "xs:0x%llx\n",xs);

	memset((void *)uddDtbSaVirAddr, 0, 1024);

	if (xso->flags & XFRM_OFFLOAD_INBOUND) {
		ret = zxdh_ipsec_dtb_in_sa_get(xs,
					       (struct T_HAL_SA_DTB_HW_IN *)(uddDtbSaVirAddr + 16));
		if (ret != 0)
			return 1;
		BttlPubDump((unsigned char *)uddDtbSaVirAddr, 0x210);

		udSaTblLen = 512 - 16;
		CmdkBttlTestSecDtbSaAdd(en_dev, E_DTB_SA_CMD_FLOW_DOWN, E_SATYPE_IN,
					uddDtbSaVirAddr, 0, udSaTblLen, 2);

	} else {
		ret = zxdh_ipsec_dtb_out_sa_get(
			xs, (struct T_HAL_SA_DTB_HW_OUT *)(uddDtbSaVirAddr + 16));
		if (ret != 0)
			return 1;
		BttlPubDump((unsigned char *)uddDtbSaVirAddr, 0x110);

		udSaTblLen = 256 - 16;
		CmdkBttlTestSecDtbSaAdd(en_dev, E_DTB_SA_CMD_FLOW_DOWN, E_SATYPE_OUT,
					uddDtbSaVirAddr, 0, udSaTblLen, 2);
	}

	return 0;
}

void zxdh_ipsec_del_sa(struct xfrm_state *xs)
{
	DH_LOG_INFO(MODULE_SEC, "zxdh ipsec del sa\n");
}

bool zxdh_ipsec_offload_ok(struct sk_buff *skb, struct xfrm_state *xs)
{
	DH_LOG_INFO(MODULE_SEC, "zxdh ipsec offload ok\n");
	return true;
}

void zxdh_ipsec_state_advance_esn(struct xfrm_state *x)
{
	DH_LOG_INFO(MODULE_SEC, "zxdh ipsec state advance esn\n");
}
void zxdh_ipsec_state_update_curlft(struct xfrm_state *x)
{
	DH_LOG_INFO(MODULE_SEC, "zxdh ipsec state update curlft\n");
}
int zxdh_ipsec_policy_add(struct xfrm_policy *x)
{
	s32 ret = 0;
	u8 aucSip[4] = { 0xc8, 0xfe, 0x00, 0x1 };
	u8 aucDip[4] = { 0xc8, 0xfe, 0x00, 0x2 };
	u8 aucSipMask[4] = { 0xff, 0xff, 0x00, 0x0 };
	u8 aucDipMask[4] = { 0xff, 0xff, 0x00, 0x0 };

	//struct xfrm_dev_offload *xdo = &x->xdo;
	//struct net_device *netdev = xdo->dev;
	struct net_device *netdev = NULL;
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct dpp_pf_info_t pf_info = { 0 };

	DH_LOG_INFO(MODULE_SEC, "zxdh ipsec policy add\n");

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	ret = dpp_vport_attr_set(&pf_info, SRIOV_VPORT_INLINE_SEC_OFFLOAD, 1);
	if (ret != 0)
		LOG_ERR("Failed to set port_attr SRIOV_VPORT_INLINE_SEC_OFFLOAD !\n");

	ret = dpp_ipsec_enc_entry_add(&pf_info, 0, aucSip, aucDip, aucSipMask, aucDipMask, 1,
				      0x80001);
	if (ret != 0)
		LOG_ERR("xfrm policy dpp_ipsec_enc_entry_add Failed!\n");

	return 0;
}
void zxdh_ipsec_policy_delete(struct xfrm_policy *x)
{
	DH_LOG_INFO(MODULE_SEC, "zxdh ipsec policy delete\n");
}
void zxdh_ipsec_policy_free(struct xfrm_policy *x)
{
	DH_LOG_INFO(MODULE_SEC, "zxdh ipsec policy free\n");
}

const struct xfrmdev_ops zxdh_xfrmdev_ops = {
	.xdo_dev_state_add = zxdh_ipsec_add_sa,
	.xdo_dev_state_delete = zxdh_ipsec_del_sa,
	.xdo_dev_offload_ok = zxdh_ipsec_offload_ok,
	//.xdo_dev_state_advance_esn = zxdh_ipsec_state_advance_esn,
	//.xdo_dev_state_update_curlft = zxdh_ipsec_state_update_curlft,
	//.xdo_dev_policy_add = zxdh_ipsec_policy_add,
	//.xdo_dev_policy_free = zxdh_ipsec_policy_free,
};
