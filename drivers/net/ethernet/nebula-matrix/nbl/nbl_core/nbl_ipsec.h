/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 nebula-matrix Limited.
 * Author: Rocky Xie <rocky.xie@nebula-matrix.com>
 */

#ifndef _NBL_IPSEC_H
#define _NBL_IPSEC_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/if_vlan.h>
#include "nbl_service.h"
#if IS_ENABLED(CONFIG_XFRM_OFFLOAD)
#include <crypto/aead.h>
#include <net/xfrm.h>
#include <net/esp.h>
#include <crypto/internal/aead.h>
#include <crypto/internal/geniv.h>

#define NBL_IPSEC_AES_128_ALG_LEN		(128 + 32)
#define NBL_IPSEC_AES_256_ALG_LEN		(256 + 32)

#define NBL_IPSEC_ICV_LEN_64			64
#define NBL_IPSEC_ICV_LEN_96			96
#define NBL_IPSEC_ICV_LEN_128			128

#define NBL_IPSEC_WINDOW_32			32
#define NBL_IPSEC_WINDOW_64			64
#define NBL_IPSEC_WINDOW_128			128
#define NBL_IPSEC_WINDOW_256			256

#define NBL_IPSEC_LIFETIME_BYTE			0
#define NBL_IPSEC_LIFETIME_PACKET		1
#define NBL_IPSEC_LIFETIME_ROUND		31
#define NBL_IPSEC_LIFETIME_REMAIN		(0x7fffffff)
#define NBL_IPSEC_REPLAY_MID_SEQ		(0X80000000L)
#define NBL_GET_SOFT_BY_HARD(hard)		(((hard) >> 2) * 3)

#define NBL_GET_KEYLEN_BY_ALG(alg_key_len)	((((alg_key_len) + 7) / 8) - 4)
#define NBL_IPSEC_KEY_LEN_TOTAL			32
#define NBL_IPSEC_AES128_KEY_LEN		16
#define NBL_IPSEC_AES_GCM_128			0
#define NBL_IPSEC_AES_GCM_256			1
#define NBL_IPSEC_SM4_GCM			2

#define NBL_IPSEC_ICV_64_TYPE			0
#define NBL_IPSEC_ICV_96_TYPE			1
#define NBL_IPSEC_ICV_128_TYPE			2

#define NBL_IPSEC_SPI_DIP__LEN			5
#define NBL_IPSEC_FLOW_TOTAL_LEN		12
#define NBL_IPSEC_FLOW_IP_LEN			4
#define NBL_IPSEC_FLOW_SIP_OFF			1
#define NBL_IPSEC_FLOW_DIP_OFF			5

#define XFRM_SA_XFLAG_OSEQ_MAY_WRAP 2
#endif

void nbl_serv_setup_xfrm_ops(struct nbl_service_ops *serv_ops_tbl);
#endif
