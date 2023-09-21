// SPDX-License-Identifier: GPL-2.0-only
#include <linux/pci.h>
#include "inspur_drm_drv.h"
#include "inspur_drm_regs.h"

void colorcur2monocur(void *data, void *out)
{
	unsigned int *col = (unsigned int *)data;
	unsigned char *mono = (unsigned char *)out;
	unsigned char pixel = 0;
	char bit_values;
	int i;

	for (i = 0; i < 64 * 64; i++) {
		if (*col >> 24 < 0xe0) {
			bit_values = 0;
		} else {
			int val = *col & 0xff;

			if (val < 0x80)
				bit_values = 1;
			else
				bit_values = 2;
		}
		col++;
		/* Copy bits into cursor byte */
		switch (i & 3) {
		case 0:
			pixel = bit_values;
			break;

		case 1:
			pixel |= bit_values << 2;
			break;

		case 2:
			pixel |= bit_values << 4;
			break;

		case 3:
			pixel |= bit_values << 6;
			*mono = pixel;
			mono++;
			pixel = 0;
			break;
		}
	}
}

#define HW_FLAG_OFFSET 0x01ffff00
#define HW_FLAG_ENABLE 0x1bd40750
unsigned char getKVMHWCursorSetting(struct inspur_drm_private *priv)
{
	unsigned int value = *(unsigned int *)(priv->fb_map + HW_FLAG_OFFSET);

	DRM_DEBUG_KMS("HW_FLAG = %x\n", value);
	return 0;
}
