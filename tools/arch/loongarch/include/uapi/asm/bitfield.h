/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
* Copyright (C) 2020 Loongson Technology Corporation Limited
*
* Author: Hanlu Li <lihanlu@loongson.cn>
*/
#ifndef __UAPI_ASM_BITFIELD_H
#define __UAPI_ASM_BITFIELD_H

/*
 *  * Damn ...  bitfields depend from byteorder :-(
 *   */
#define __BITFIELD_FIELD(field, more)					\
	more								\
	field;

#endif /* __UAPI_ASM_BITFIELD_H */
