// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include "mce.h"
#include "mce_lib.h"
#include "mce_npu.h"
#include "mce_n20/mce_hw_n20.h"

int mce_npu_download_firmware(struct mce_hw *hw)
{
	hw->ops->npu_download_firmware(hw);
	return 0;
}
