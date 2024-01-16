// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of tsse driver for Linux
 *
 * Copyright © 2023 Montage Technology. All rights reserved.
 */

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/mm.h>
#include <linux/pci.h>
#include <linux/string.h>
#include <linux/firmware.h>

#include "tsse_dev.h"
#include "tsse_service.h"

#define SEARCH_PATTERN "MT_CFG_BUILD_VERSION_DETAIL"
#define SEARCH_PATTERN_LEN 28

int fw_send_msg(struct tsse_ipc *tsseipc, struct ipc_msg *msg)
{
	u8 *h2d;
	u32 int_reg;
	u32 rc;

	mutex_lock(&tsseipc->list_lock);

	int_reg = readl(tsseipc->virt_addr + HOST2MAIN_INTR_SET_OFFSET);
	if ((int_reg & IPC_REGISTER_INT_SET) != 0) {
		rc = -1;
		mutex_unlock(&tsseipc->list_lock);
		return rc;
	}
	h2d = (u8 *)(tsseipc->virt_addr + HOST2MAIN_IPC_OFFSET);
	memcpy_toio(h2d, msg, sizeof(struct ipc_header));
	memcpy_toio(h2d + sizeof(struct ipc_header), (u32 *)msg->i_data,
		    msg->header.i_len - sizeof(struct ipc_header));
	writel(0x1, tsseipc->virt_addr + HOST2MAIN_INTR_SET_OFFSET);

	dev_info(tsseipc->dev, "notify device to get firmware\n");
	mutex_unlock(&tsseipc->list_lock);
	return 0;
}

void fw_free(void *msg_t)
{
	struct tsse_msg *tssemsg;
	struct ipc_msg *payload;

	payload = (struct ipc_msg *)msg_t;
	tssemsg = container_of(payload, struct tsse_msg, ipc_payload);

	kvfree(tssemsg);
}

int get_firmware_version(char *fw_buffer, uint32_t buffer_len, char *fw_version)
{
	char *pattern;
	char *space_ch = " ";
	uint32_t pattern_i = 0, buffer_i = 0;
	uint32_t pattern_len = SEARCH_PATTERN_LEN - 1; // Not include "\0"
	uint32_t version_start = 0;
	uint32_t version_len = 0;

	pattern = kzalloc(SEARCH_PATTERN_LEN, GFP_KERNEL);
	if (!pattern)
		return -1;

	snprintf(pattern, SEARCH_PATTERN_LEN, SEARCH_PATTERN);

	while (buffer_i < buffer_len) {
		if (pattern[pattern_i] == fw_buffer[buffer_i]) {
			buffer_i++;
			pattern_i++;
		}
		if (pattern_i == pattern_len) {
			break;	// pattern found
		} else if ((buffer_i < buffer_len) &&
			 (pattern[pattern_i] != fw_buffer[buffer_i])) {
			// mismatch after pattern_i matches
			if (pattern_i != 0) {
				// since the pattern has no common prefix, when mismatch,
				// the next compare should start from pattern beginning
				pattern_i = 0;
			} else {
				buffer_i++;
			}
		}
	}
	kfree(pattern);
	if (pattern_i == pattern_len) {
		buffer_i++;
		version_start = buffer_i;
		while (buffer_i < buffer_len) {
			if (fw_buffer[buffer_i] == space_ch[0]) {
				version_len = buffer_i - version_start;
				strscpy(fw_version, fw_buffer + version_start, version_len + 1);
				return 0;
			}
			buffer_i++;
		}
	}
	return -1;
}

void fw_service(void *tsseipc_t, void *msg_t)
{
	void __iomem *fw;
	uint32_t size;
	uint32_t task_offset;
	struct fw_load *fw_task;
	struct tsse_dev *tdev;
	struct tsse_ipc *tsseipc = (struct tsse_ipc *)tsseipc_t;
	struct ipc_msg *msg = (struct ipc_msg *)msg_t;

	task_offset = sizeof(struct msg_info);
	fw_task = (struct fw_load *)(msg->i_data +
				     task_offset / sizeof(uint32_t));

	tdev = pci_to_tsse_dev(tsseipc->pdev);
	if (!tdev || !tdev->fw) {
		fw_task->result = 1;
		fw_task->size = 0;
		dev_info(tsseipc->dev, "firmware loading failed\n");
		fw_send_msg(tsseipc, msg);
		fw_free(msg);
		return;
	}

	fw_task->result = 0;
	fw_task->size = tdev->fw->size;
	size = tdev->fw->size;
	fw = tsseipc->virt_addr + fw_task->offset + FW_BASE;

	memcpy_toio((u8 *)fw, tdev->fw->data, size);
	dev_info(tsseipc->dev, "firmware loading done\n");
	fw_send_msg(tsseipc, msg);
	fw_free(msg);

	dev_info(tsseipc->dev, "firmware version: %s\n", tdev->fw_version);

	if (tdev->fw) {
		release_firmware(tdev->fw);
		tdev->fw = NULL;
	}
}

int tsse_fw_load(struct pci_dev *pdev)
{
	int result;
	struct tsse_dev *tdev = pci_to_tsse_dev(pdev);

	result = request_firmware(&tdev->fw, TSSE_FIRMWARE, &pdev->dev);
	if (result)
		dev_err(&pdev->dev, "%s failed\n", __func__);
	return result;
}
