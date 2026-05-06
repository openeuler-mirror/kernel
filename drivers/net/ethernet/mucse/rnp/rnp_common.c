// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 - 2026 Mucse Corporation. */

#include <linux/module.h>

unsigned int rnp_loglevel;
module_param(rnp_loglevel, uint, 0600);
