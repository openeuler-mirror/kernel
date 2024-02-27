/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of tsse driver for Linux
 *
 * Copyright © 2023 Montage Technology. All rights reserved.
 */

#ifndef __TSSE_FW_SERVICE_H__
#define __TSSE_FW_SERVICE_H__

#define FW_BASE 0x7000000
#define TSSE_FIRMWARE "tsse_firmware.bin"

void fw_service(void *tsseipc_t, void *msg_t);
int tsse_fw_load(struct pci_dev *pdev);
int get_firmware_version(char *fw_buffer, uint32_t buffer_len, char *fw_version);
#endif
