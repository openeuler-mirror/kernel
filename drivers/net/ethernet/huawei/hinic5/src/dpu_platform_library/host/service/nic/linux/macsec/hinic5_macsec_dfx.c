/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_macsec_dfx.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : macsec dfx related code
 */
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/semaphore.h>

#include "hinic5_mt.h"
#include "hinic5_crm.h"
#include "hinic5_nic_dev.h"

#include "macsec_mpu_cmd_defs.h"
#include "macsec_pub_cmd.h"
#include "hinic5_macsec_common.h"
#include "hinic5_macsec_dfx.h"

void himacsec_dfx_convert_key_length(u32 *key_length, u32 chip_key_len_val)
{
	if (chip_key_len_val == HIMACSEC_REG_KEY_LENGTH_128)
		*key_length = CRYPT_KEY_LENGTH_128;
	else if (chip_key_len_val == HIMACSEC_REG_KEY_LENGTH_256)
		*key_length = CRYPT_KEY_LENGTH_256;
	else
		*key_length = chip_key_len_val;
}

void himacsec_dfx_show_enc_sa(struct hinic5_nic_dev *nic_dev, macsec_sa_info_s *enc_sa)
{
	u32 key_len;

	himacsec_dfx_convert_key_length(&key_len, enc_sa->current_key_length);
	macsec_info(nic_dev->lld_dev->dev,
		    "%s: encryption sa: sci=%llx, an=%d, algorithm=%d[0: AES, 1:SM4], offset=0x%x, key length=%d[0: 128, 1: 256], xpn enable=%d, ssci=0x%x",
		    nic_dev->netdev->name, enc_sa->sci, enc_sa->an,
		    enc_sa->current_crypto_algo, enc_sa->confidentiality_offset,
		    enc_sa->current_key_length, enc_sa->extended_pn_enable,
		    enc_sa->ssci);
	// encrytion info
	macsec_info(nic_dev->lld_dev->dev, "%s: encryption sa: sci=%llx, an=%d, pn threshold=0x%llx, next pn=0x%llx, enable transmit=%d",
		    nic_dev->netdev->name, enc_sa->sci, enc_sa->an,
		    enc_sa->pn_th, enc_sa->next_pn, enc_sa->enable_transmit);
}

void himacsec_dfx_show_dec_sa(struct hinic5_nic_dev *nic_dev, macsec_sa_info_s *dec_sa)
{
	u32 key_len;

	himacsec_dfx_convert_key_length(&key_len, dec_sa->current_key_length);
	macsec_info(nic_dev->lld_dev->dev,
		    "%s: decryption sa: sci=%llx, an=%d, algorithm=%d[0: AES, 1:SM4], offset=0x%x, key length=%d[0: 128, 1: 256], xpn enable=%d, ssci=0x%x",
		    nic_dev->netdev->name, dec_sa->sci, dec_sa->an,
		    dec_sa->current_crypto_algo, dec_sa->confidentiality_offset,
		    dec_sa->current_key_length, dec_sa->extended_pn_enable,
		    dec_sa->ssci);
	// decrytion info
	macsec_info(nic_dev->lld_dev->dev, "%s: decryption sa: sci=%llx, an=%d, replay=%d, windows=0x%x, enable receive=%d, lowest pn=0x%llx",
		    nic_dev->netdev->name, dec_sa->sci, dec_sa->an,
		    dec_sa->replay_protect, dec_sa->replay_window,
		    dec_sa->enable_receive, dec_sa->lowest_pn);
}

void himacsec_dfx_show_sa(struct hinic5_nic_dev *nic_dev,
			  macsec_sa_info_s *sa_info, crypt_direction_e direct)
{
	if (direct == MACSEC_OUTBOUND)
		himacsec_dfx_show_enc_sa(nic_dev, sa_info);
	else
		himacsec_dfx_show_dec_sa(nic_dev, sa_info);
}

void himacsec_dfx_show_enc_sc(struct hinic5_nic_dev *nic_dev, macsec_sc_info_s *enc_sc)
{
	macsec_info(nic_dev->lld_dev->dev,
		    "%s: encryption sc: sci=%llx, protect_frames=%d, protection_mode=%d, include_sci=%d, use_scb=%d, use_es=%d, encodingsa=%d",
		    nic_dev->netdev->name, enc_sc->sci,
		    enc_sc->protect_frames, enc_sc->protection_mode,
		    enc_sc->include_sci_enable, enc_sc->use_scb_enable,
		    enc_sc->use_es_enable, enc_sc->encoding_sa);
}

void himacsec_dfx_show_dec_sc(struct hinic5_nic_dev *nic_dev, macsec_sc_info_s *dec_sc)
{
	macsec_info(nic_dev->lld_dev->dev, "%s: decryption sc: sci=%llx, validate_frames=%d",
		    nic_dev->netdev->name, dec_sc->sci, dec_sc->validate_frames);
}

void himacsec_dfx_show_sc(struct hinic5_nic_dev *nic_dev,
			  macsec_sc_info_s *sc_info, crypt_direction_e direct)
{
	if (direct == MACSEC_OUTBOUND)
		himacsec_dfx_show_enc_sc(nic_dev, sc_info);
	else
		himacsec_dfx_show_dec_sc(nic_dev, sc_info);
}
