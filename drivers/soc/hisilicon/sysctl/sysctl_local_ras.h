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
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http:
 */

#ifndef _RP_INTERRUPT_H
#define _RP_INTERRUPT_H

enum sysctl_bios_err {
	MODULE_LPC_ERR = 9,
	MODULE_USB2_ERR = 14,
	MODULE_USB3_ERR = 15,
};

struct sysctl_validation_bits {
	u32 soc_id_vald : 1;
	u32 socket_id_vald : 1;
	u32 nimbus_id_vald : 1;
	u32 module_id_vald : 1;
	u32 submod_id_vald : 1;
	u32 err_sever_vald : 1;
	u32 err_misc0_vald : 1;
	u32 err_misc1_vald : 1;
	u32 err_misc2_vald : 1;
	u32 err_misc3_vald : 1;
	u32 err_misc4_vald : 1;
	u32 err_addr_vald : 1;
	u32 reserv : 20;
};

struct sysctl_local_ras_cper {
	struct sysctl_validation_bits validation_bits;
	u8 version;
	u8 soc_id;
	u8 socket_id;
	u8 nimbus_id;
	u8 module_id;
	u8 sub_mod_id;
	u8 err_severity;
	u8 resv1;
	u32 err_misc0;
	u32 err_misc1;
	u32 err_misc2;
	u32 err_misc3;
	u32 err_misc4;
	u32 err_addrl;
	u32 err_addrh;
};

int hip_sysctl_local_ras_init(void);
void hip_sysctl_local_ras_exit(void);

#endif
