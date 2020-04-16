/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Hisilicon Limited, All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef _SYSCTL_DFX_H_
#define _SYSCTL_DFX_H_

int sysctl_proc_init(void);
void sysctl_proc_exit(void);
void sysctl_dfx_do_ras(struct acpi_hest_generic_data *gdata);

#endif /* _SYSCTL_DFX_H_ */
