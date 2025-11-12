/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * HYGON Platform Security Processor (PSP) driver interface
 *
 * Copyright (C) 2024 Hygon Info Technologies Ltd.
 *
 * Author: Liyang Han <hanliyang@hygon.cn>
 */

#ifndef __PSP_HYGON_H__
#define __PSP_HYGON_H__

#include <linux/types.h>

/*****************************************************************************/
/***************************** CSV interface *********************************/
/*****************************************************************************/

/**
 * Guest/platform management commands for CSV
 */
enum csv_cmd {
	CSV_CMD_HGSC_CERT_IMPORT        = 0x300,
	CSV_CMD_MAX,
};

/**
 * struct csv_data_hgsc_cert_import - HGSC_CERT_IMPORT command parameters
 *
 * @hgscsk_cert_address: HGSCSK certificate chain
 * @hgscsk_cert_len: len of HGSCSK certificate
 * @hgsc_cert_address: HGSC certificate chain
 * @hgsc_cert_len: len of HGSC certificate
 */
struct csv_data_hgsc_cert_import {
	u64 hgscsk_cert_address;        /* In */
	u32 hgscsk_cert_len;            /* In */
	u32 reserved;                   /* In */
	u64 hgsc_cert_address;          /* In */
	u32 hgsc_cert_len;              /* In */
} __packed;

#ifdef CONFIG_CRYPTO_DEV_SP_PSP

int psp_do_cmd(int cmd, void *data, int *psp_ret);

#else  /* !CONFIG_CRYPTO_DEV_SP_PSP */

static inline int psp_do_cmd(int cmd, void *data, int *psp_ret) { return -ENODEV; }

#endif /* CONFIG_CRYPTO_DEV_SP_PSP */

typedef int (*p2c_notifier_t)(uint32_t id, uint64_t data);

#ifdef CONFIG_HYGON_PSP2CPU_CMD

int psp_register_cmd_notifier(uint32_t cmd_id, p2c_notifier_t notifier);
int psp_unregister_cmd_notifier(uint32_t cmd_id, p2c_notifier_t notifier);

#else	/* !CONFIG_HYGON_PSP2CPU_CMD */

int psp_register_cmd_notifier(uint32_t cmd_id, p2c_notifier_t notifier) { return -ENODEV; }
int psp_unregister_cmd_notifier(uint32_t cmd_id, p2c_notifier_t notifier) { return -ENODEV; }

#endif	/* CONFIG_HYGON_PSP2CPU_CMD */

#endif /* __PSP_HYGON_H__ */
