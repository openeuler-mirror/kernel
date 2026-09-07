// SPDX-License-Identifier: GPL-2.0
/*
 * crc32.c - CRC32 and CRC32C using LoongArch crc* instructions
 *
 * Module based on mips/crypto/crc32-mips.c
 *
 * Copyright (C) 2014 Linaro Ltd <yazen.ghannam@linaro.org>
 * Copyright (C) 2018 MIPS Tech, LLC
 * Copyright (C) 2020-2023 Loongson Technology Corporation Limited
 */

#include <linux/jump_label.h>
#include <crypto/internal/hash.h>

#include <asm/cpufeature.h>
#include <asm/unaligned.h>

extern u32 __pure crc32_le_base(u32 crc, unsigned char const *p, size_t len);
extern u32 __pure __crc32c_le_base(u32 crc, unsigned char const *p, size_t len);

#define _CRC32(crc, value, size, type)			\
do {							\
	__asm__ __volatile__(				\
		#type ".w." #size ".w" " %0, %1, %0\n\t"\
		: "+r" (crc)				\
		: "r" (value)				\
		: "memory");				\
} while (0)

#define CRC32(crc, value, size)		_CRC32(crc, value, size, crc)
#define CRC32C(crc, value, size)	_CRC32(crc, value, size, crcc)

u32 __pure crc32_le(u32 crc_, unsigned char const *p, size_t len)
{
	u32 crc = crc_;

	if (!static_branch_likely(&cpu_crc32_support))
		return crc32_le_base(crc, p, len);

	while (len >= sizeof(u64)) {
		u64 value = get_unaligned_le64(p);

		CRC32(crc, value, d);
		p += sizeof(u64);
		len -= sizeof(u64);
	}

	if (len & sizeof(u32)) {
		u32 value = get_unaligned_le32(p);

		CRC32(crc, value, w);
		p += sizeof(u32);
	}

	if (len & sizeof(u16)) {
		u16 value = get_unaligned_le16(p);

		CRC32(crc, value, h);
		p += sizeof(u16);
	}

	if (len & sizeof(u8)) {
		u8 value = *p++;

		CRC32(crc, value, b);
	}

	return crc;
}

u32 __pure __crc32c_le(u32 crc_, unsigned char const *p, size_t len)
{
	u32 crc = crc_;

	if (!static_branch_likely(&cpu_crc32_support))
		return __crc32c_le_base(crc, p, len);

	while (len >= sizeof(u64)) {
		u64 value = get_unaligned_le64(p);

		CRC32C(crc, value, d);
		p += sizeof(u64);
		len -= sizeof(u64);
	}

	if (len & sizeof(u32)) {
		u32 value = get_unaligned_le32(p);

		CRC32C(crc, value, w);
		p += sizeof(u32);
	}

	if (len & sizeof(u16)) {
		u16 value = get_unaligned_le16(p);

		CRC32C(crc, value, h);
		p += sizeof(u16);
	}

	if (len & sizeof(u8)) {
		u8 value = *p++;

		CRC32C(crc, value, b);
	}

	return crc;
}
