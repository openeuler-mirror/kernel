// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#include "spfc_utils.h"
#include "unf_log.h"
#include "unf_common.h"

void spfc_cpu_to_big64(void *addr, u32 size)
{
	u32 index = 0;
	u32 cnt = 0;
	u64 *temp = NULL;

	FC_CHECK_VALID(addr, dump_stack(); return);
	FC_CHECK_VALID((size % SPFC_QWORD_BYTE) == 0, dump_stack(); return);

	temp = (u64 *)addr;
	cnt = SPFC_SHIFT_TO_U64(size);

	for (index = 0; index < cnt; index++) {
		*temp = cpu_to_be64(*temp);
		temp++;
	}
}

void spfc_big_to_cpu64(void *addr, u32 size)
{
	u32 index = 0;
	u32 cnt = 0;
	u64 *temp = NULL;

	FC_CHECK_VALID(addr, dump_stack(); return);
	FC_CHECK_VALID((size % SPFC_QWORD_BYTE) == 0, dump_stack(); return);

	temp = (u64 *)addr;
	cnt = SPFC_SHIFT_TO_U64(size);

	for (index = 0; index < cnt; index++) {
		*temp = be64_to_cpu(*temp);
		temp++;
	}
}

void spfc_cpu_to_big32(void *addr, u32 size)
{
	unf_cpu_to_big_end(addr, size);
}

void spfc_big_to_cpu32(void *addr, u32 size)
{
	if (size % UNF_BYTES_OF_DWORD)
		dump_stack();

	unf_big_end_to_cpu(addr, size);
}

void spfc_cpu_to_be24(u8 *data, u32 value)
{
	data[ARRAY_INDEX_0] = (value >> UNF_SHIFT_16) & UNF_MASK_BIT_7_0;
	data[ARRAY_INDEX_1] = (value >> UNF_SHIFT_8) & UNF_MASK_BIT_7_0;
	data[ARRAY_INDEX_2] = value & UNF_MASK_BIT_7_0;
}

u32 spfc_big_to_cpu24(u8 *data)
{
	return (data[ARRAY_INDEX_0] << UNF_SHIFT_16) |
	       (data[ARRAY_INDEX_1] << UNF_SHIFT_8) | data[ARRAY_INDEX_2];
}

void spfc_print_buff(u32 dbg_level, void *buff, u32 size)
{
	u32 *spfc_buff = NULL;
	u32 loop = 0;
	u32 index = 0;

	FC_CHECK_VALID(buff, dump_stack(); return);
	FC_CHECK_VALID(0 == (size % SPFC_DWORD_BYTE), dump_stack(); return);

	if ((dbg_level) <= unf_dgb_level) {
		spfc_buff = (u32 *)buff;
		loop = size / SPFC_DWORD_BYTE;

		for (index = 0; index < loop; index++) {
			spfc_buff = (u32 *)buff + index;
			FC_DRV_PRINT(UNF_LOG_NORMAL,
				     UNF_MAJOR, "Buff DW%u 0x%08x.", index, *spfc_buff);
		}
	}
}

u32 spfc_log2n(u32 val)
{
	u32 result = 0;
	u32 logn = (val >> UNF_SHIFT_1);

	while (logn) {
		logn >>= UNF_SHIFT_1;
		result++;
	}

	return result;
}
