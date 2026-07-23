// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "zxic_common.h"

#if ZXIC_REAL("")
u32 g_zxic_malloc_num;
u32 g_zxic_malloc_size;
u32 g_zxic_vmalloc_num;
u32 g_zxic_vmalloc_size;
u32 g_zxic_byte_swap_en = 1;
u32 g_zxic_comm_channel_max = 4;
#endif

#if ZXIC_REAL("")
void ic_comm_free_record(void)
{
	if (g_zxic_malloc_num > 0)
		g_zxic_malloc_num--;
	else
		ZXIC_COMM_TRACE_ERROR("Note:g_zxicp_malloc_num is zero now\n");
}
void ic_comm_vfree_record(void)
{
	if (g_zxic_vmalloc_num > 0)
		g_zxic_vmalloc_num--;
	else
		ZXIC_COMM_TRACE_ERROR("Note:g_zxicp_vmalloc_num is zero now\n");
}
void *ic_comm_malloc_memory(u32 size)
{
	if (size > ZXIC_MALLOC_MAX_B_SIZE) {
		ZXIC_COMM_TRACE_ERROR("malloc size err, size more than 200M\n");
		return ZXIC_NULL;
	}
	if (g_zxic_malloc_num < ZXIC_UINT32_MAX) {
		g_zxic_malloc_num++;
	} else {
		ZXIC_COMM_TRACE_ERROR("Note:g_zxicp_malloc_num is maxvalue now, reset 0\n");
		g_zxic_malloc_num = 0;
	}

	if (g_zxic_malloc_size < (ZXIC_UINT32_MAX - size)) {
		g_zxic_malloc_size += size;
	} else {
		ZXIC_COMM_TRACE_INFO(
			"Note:g_zxic_malloc_size[0x%x] and size[0x%x] sum is over maxvalue now, reset 0\n",
			g_zxic_malloc_size, size);
		g_zxic_malloc_size = 0;
	}

	return kmalloc(size, GFP_KERNEL);
}
void *ic_comm_vmalloc_memory(u32 size)
{
	if (size > ZXIC_MALLOC_MAX_B_SIZE) {
		ZXIC_COMM_TRACE_ERROR("malloc size err, size more than 200M\n");
		return ZXIC_NULL;
	}
	if (g_zxic_vmalloc_num < ZXIC_UINT32_MAX) {
		g_zxic_vmalloc_num++;
	} else {
		ZXIC_COMM_TRACE_ERROR("Note:g_zxicp_vmalloc_num is maxvalue now, reset 0\n");
		g_zxic_vmalloc_num = 0;
	}

	if (g_zxic_vmalloc_size < (ZXIC_UINT32_MAX - size)) {
		g_zxic_vmalloc_size += size;
	} else {
		ZXIC_COMM_TRACE_INFO(
			"Note:g_zxic_vmalloc_size[0x%x] and size[0x%x] sum is over maxvalue now, reset 0\n",
			g_zxic_vmalloc_size, size);
		g_zxic_vmalloc_size = 0;
	}

	return vmalloc(size);
}
#endif

#if ZXIC_REAL("")
// void zxic_comm_sleep(u32 milliseconds)
// {

// #ifndef ZXIC_FOR_LLT
// #ifdef ZXIC_OS_WIN
// Sleep(milliseconds);
// #else
// ZXIC_COMM_CHECK_INDEX_MUL_OVERFLOW_NONE((u32)milliseconds, 1000);

// msleep(milliseconds);
// #endif
// #endif
// }
void zxic_comm_udelay(u32 microseconds)
{
#ifndef ZXIC_FOR_LLT

	ZXIC_COMM_CHECK_INDEX_SUB_OVERFLOW_NONE(microseconds, 1);

	udelay(microseconds);
#endif
}
void zxic_comm_delay(u32 milliseconds)
{
#ifndef ZXIC_FOR_LLT
	// u32 i = 0;

	ZXIC_COMM_CHECK_INDEX_SUB_OVERFLOW_RETURN(milliseconds, 1);
	// while (--milliseconds != 0)
	// {
	// for (i = 0; i < 600; i++);
	// }
	mdelay(milliseconds);
#endif
}
void zxic_comm_msleep(u32 millisecond)
{
#ifndef ZXIC_FOR_LLT
#ifdef ZXIC_OS_WIN
	Sleep(millisecond);
#else
	msleep(millisecond);
#endif
#endif
}
long zxic_comm_get_ticks_ms(void)
{
#ifdef ZXIC_OS_WIN
	return (int)GetTickCount();
#else
	struct timespec64 tv = { 0 };

	get_timespec64(&tv, ZXIC_NULL);
	return 1000L * tv.tv_sec + (long)tv.tv_nsec / 1000;
#endif
}
#endif

#if ZXIC_REAL("")
u32 zxic_comm_is_big_endian(void)
{
	union zxic_endian_u c_data;

	c_data.a = 1;

	if (c_data.b == 1)
		return 0;
	else
		return 1;
}
void zxic_comm_swap(u8 *p_uc_data, u32 dw_byte_len)
{
	u32 dw_byte_num = 0;
	u8 uc_byte_mode = 0;
	u32 uc_is_big_flag = 0;
	u32 i = 0;
	u16 *p_w_tmp = ZXIC_NULL;
	u32 *p_dw_tmp = ZXIC_NULL;

	if (g_zxic_byte_swap_en) {
		p_dw_tmp = (u32 *)(p_uc_data);

		uc_is_big_flag = zxic_comm_is_big_endian();

		if (uc_is_big_flag)
			return;
		dw_byte_num = dw_byte_len >> 2;
		uc_byte_mode = dw_byte_len % 4 & 0xff;

		for (i = 0; i < dw_byte_num; i++) {
			(*p_dw_tmp) = ZXIC_COMM_CONVERT32(*p_dw_tmp);
			p_dw_tmp++;
		}

		if (uc_byte_mode > 1) {
			p_w_tmp = (u16 *)(p_dw_tmp);
			(*p_w_tmp) = ZXIC_COMM_CONVERT16(*p_w_tmp);
		}
	}
}
u64 ZXIC_COMM_COUNTER64_BUILD(u32 hi, u32 lo)
{
	u64 value = hi;

	value = value << 32;
	value = value | lo;

	return value;
}
#endif

#if ZXIC_REAL("bit")
u32 zxic_comm_write_bits(u8 *p_base, u32 base_size_bit, u32 data, u32 start_bit, u32 end_bit)
{
	u32 len = 0;
	u32 start_byte_index = 0;
	u32 end_byte_index = 0;
	u8 mask_value = 0;
	u32 byte_num = 0;
	u32 buffer_size = 0;

	if (0 != (base_size_bit % 8)) {
		ZXIC_COMM_TRACE_ERROR("\n buffer must be:%d", __LINE__);
		//assert(0);
		return ZXIC_BIT_STREAM_INDEX_ERR;
	}

	if (start_bit > end_bit) {
		ZXIC_COMM_TRACE_ERROR("\nend_bit cannot be less than start_bit:%d", __LINE__);
		//assert(0);
		return ZXIC_BIT_STREAM_INDEX_ERR;
	}

	if (base_size_bit < end_bit) {
		ZXIC_COMM_TRACE_ERROR(
			"\nend_bit exceeds the base_size!line:%d,base_size_bit:%d end_bit:%d",
			__LINE__, base_size_bit, end_bit);
		//assert(0);
		return ZXIC_BIT_STREAM_INDEX_ERR;
	}

	ZXIC_COMM_CHECK_INDEX_SUB_OVERFLOW(end_bit, start_bit);
	ZXIC_COMM_CHECK_INDEX_ADD_OVERFLOW(end_bit - start_bit, 1);

	len = end_bit - start_bit + 1;
	buffer_size = base_size_bit / 8;

	ZXIC_COMM_CHECK_INDEX_SUB_OVERFLOW(buffer_size, 1);
	ZXIC_COMM_CHECK_INDEX_ADD_OVERFLOW(buffer_size, 1);

	while (0 != (buffer_size & (buffer_size - 1)))
		buffer_size += 1;

	if (buffer_size != base_size_bit / 8) {
		ZXIC_COMM_TRACE_ALL("\n buffer size[0x%x] is not 2^n: add up to [0x%x]",
				    base_size_bit / 8, buffer_size);
	}

	ZXIC_COMM_CHECK_INDEX(len, 1, 32);

	if (data > (u32)(0xffffffff >> (32 - len))) {
		ZXIC_COMM_PRINT("\nValue is too big to write in the bit field!:%d,data:%x,len:%x",
				__LINE__, data, (u32)(0xffffffff >> (32 - len)));
		return ZXIC_BIT_STREAM_DATA_TOO_BIG;
	}

	end_byte_index = (end_bit >> 3);
	start_byte_index = (start_bit >> 3);

	if (start_byte_index == end_byte_index) {
		mask_value = ((0xFE << (7 - (start_bit & 7))) & 0xff);
		mask_value |= (((1 << (7 - (end_bit & 7))) - 1) & 0xff);
		p_base[end_byte_index] &= mask_value;
		p_base[end_byte_index] |= (((data << (7 - (end_bit & 7)))) & 0xff);
		return ZXIC_OK;
	}

	if (7 != (end_bit & 7)) {
		mask_value = ((0x7f >> (end_bit & 7)) & 0xff);
		p_base[end_byte_index] &= mask_value;
		p_base[end_byte_index] |= ((data << (7 - (end_bit & 7))) & 0xff);
		end_byte_index--;
		data >>= 1 + (end_bit & 7);
	}

	for (byte_num = end_byte_index; byte_num > start_byte_index; byte_num--) {
		/* critical */
		p_base[byte_num & (buffer_size - 1)] = data & 0xff;
		data >>= 8;
	}

	mask_value = ((0xFE << (7 - (start_bit & 7))) & 0xff);
	p_base[byte_num] &= mask_value;
	p_base[byte_num] |= data;

	return ZXIC_OK;
}
u32 zxic_comm_read_bits(u8 *p_base, u32 base_size_bit, u32 *p_data, u32 start_bit, u32 end_bit)
{
	u32 len = 0;
	u32 start_byte_index = 0;
	u32 end_byte_index = 0;
	u32 byte_num = 0;
	u32 buffer_size = 0;

	if (0 != (base_size_bit % 8)) {
		ZXIC_COMM_TRACE_ERROR("\n buffer must be:%d", __LINE__);
		return ZXIC_BIT_STREAM_INDEX_ERR;
	}

	if (start_bit > end_bit) {
		ZXIC_COMM_TRACE_ERROR("\nend_bit cannot be less than start_bit:%d", __LINE__);
		return ZXIC_BIT_STREAM_INDEX_ERR;
	}

	if (base_size_bit < end_bit) {
		ZXIC_COMM_TRACE_ERROR("\nend_bit exceeds the base_size:%d,end_bit:%d", __LINE__,
				      end_bit);
		return ZXIC_BIT_STREAM_INDEX_ERR;
	}

	len = end_bit - start_bit + 1;
	buffer_size = base_size_bit / 8;

	ZXIC_COMM_CHECK_INDEX_SUB_OVERFLOW(buffer_size, 1);

	while (0 != (buffer_size & (buffer_size - 1)))
		buffer_size += 1;

	if (buffer_size != base_size_bit / 8) {
		ZXIC_COMM_TRACE_ALL("\n buffer size[0x%x] is not 2^n: add up to [0x%x]",
				    base_size_bit / 8, buffer_size);
	}

	*p_data = 0;

	ZXIC_COMM_CHECK_INDEX(len, 1, 32);

	end_byte_index = (end_bit >> 3);
	start_byte_index = (start_bit >> 3);

	if (start_byte_index == end_byte_index) {
		*p_data = (u32)(((p_base[start_byte_index] >> (7U - (end_bit & 7))) &
				 (0xff >> (8U - len))) &
				0xff);
		return ZXIC_OK;
	}

	if (start_bit & 7) {
		*p_data = (p_base[start_byte_index] & (0xff >> (start_bit & 7))) & ZXIC_UINT8_MASK;
		start_byte_index++;
	}

	for (byte_num = start_byte_index; byte_num < end_byte_index; byte_num++) {
		*p_data <<= 8;

		ZXIC_COMM_CHECK_INDEX_ADD_OVERFLOW(*p_data, p_base[byte_num]);
		*p_data += p_base[byte_num];
	}

	*p_data <<= 1 + (end_bit & 7);
	/* critical */
	ZXIC_COMM_CHECK_INDEX_ADD_OVERFLOW(
		*p_data, (((p_base[byte_num & (buffer_size - 1)] & (0xff << (7 - (end_bit & 7)))) >>
			   (7 - (end_bit & 7))) &
			  0xff));
	*p_data += ((p_base[byte_num & (buffer_size - 1)] & (0xff << (7 - (end_bit & 7)))) >>
		    (7 - (end_bit & 7))) &
		   0xff;

	return ZXIC_OK;
}
u32 zxic_comm_write_bits_ex(u8 *p_base, u32 base_size_bit, u32 data, u32 msb_start_pos, u32 len)
{
	u32 rtn = ZXIC_OK;

	ZXIC_COMM_CHECK_POINT(p_base);

	ZXIC_COMM_CHECK_INDEX_SUB_OVERFLOW(base_size_bit, 1);
	ZXIC_COMM_CHECK_INDEX_ADD_OVERFLOW(base_size_bit - 1, msb_start_pos);
	ZXIC_COMM_CHECK_INDEX_ADD_OVERFLOW(base_size_bit - 1 - msb_start_pos, len);
	ZXIC_COMM_CHECK_INDEX_SUB_OVERFLOW(base_size_bit - 1 - msb_start_pos + len, 1);

	rtn = zxic_comm_write_bits(p_base, base_size_bit, data, (base_size_bit - 1 - msb_start_pos),
				   (base_size_bit - 1 - msb_start_pos + len - 1));

	return rtn;
}
u32 zxic_comm_read_bits_ex(u8 *p_base, u32 base_size_bit, u32 *p_data, u32 msb_start_pos, u32 len)
{
	u32 rtn = ZXIC_OK;

	ZXIC_COMM_CHECK_POINT(p_base);
	ZXIC_COMM_CHECK_POINT(p_data);

	ZXIC_COMM_CHECK_INDEX_SUB_OVERFLOW(base_size_bit, 1);
	ZXIC_COMM_CHECK_INDEX_ADD_OVERFLOW(base_size_bit - 1, msb_start_pos);
	ZXIC_COMM_CHECK_INDEX_ADD_OVERFLOW(base_size_bit - 1 - msb_start_pos, len);
	ZXIC_COMM_CHECK_INDEX_SUB_OVERFLOW(base_size_bit - 1 - msb_start_pos + len, 1);

	rtn = zxic_comm_read_bits(p_base, base_size_bit, p_data,
				  (base_size_bit - 1 - msb_start_pos),
				  (base_size_bit - 1 - msb_start_pos + len - 1));
	return rtn;
}
#endif

#if ZXIC_REAL("")
s32 ic_comm_snprintf_s(char *buffer, size_t sizeofbuf, size_t count, const char *format, ...)
{
	va_list ap;
	s32 ret = -1;

	if ((buffer == ZXIC_NULL) || (format == ZXIC_NULL)) {
		ZXIC_COMM_TRACE_ERROR("\n ZXIC %s:%d[Error:POINT NULL] ! FUNCTION : %s!\n",
				      __FILE__, __LINE__, __func__);
		return ret;
	}
	if (!count) {
		ZXIC_COMM_TRACE_ERROR("\n ZXIC %s:%d[Error:count err], FUNCTION : %s!\n", __FILE__,
				      __LINE__, __func__);
		return ret;
	}
	va_start(ap, format);
	ret = ZXIC_COMM_VSNPRINTF_S(buffer, sizeofbuf, count, format, ap);
	va_end(ap);

	if (ret == -1) {
		ZXIC_COMM_TRACE_ERROR("\n ZXIC %s:%d[Error:snprintf_s err], FUNCTION : %s!\n",
				      __FILE__, __LINE__, __func__);
	}
	return ret;
}
s32 ic_comm_vsnprintf_s(char *buffer, size_t sizeofbuf, size_t count, const char *format,
			va_list ap)
{
	s32 ret = -1;

	if ((buffer == ZXIC_NULL) || (format == ZXIC_NULL)) {
		ZXIC_COMM_TRACE_ERROR("\n ZXIC %s:%d[Error:POINT NULL] ! FUNCTION : %s!\n",
				      __FILE__, __LINE__, __func__);
		return ret;
	}
	if (!count) {
		ZXIC_COMM_TRACE_ERROR("\n ZXIC %s:%d[Error:count err], FUNCTION : %s!\n", __FILE__,
				      __LINE__, __func__);
		return ret;
	}
	if (count < sizeofbuf)
		sizeofbuf = count;
#ifdef ZXIC_OS_WIN
	ret = _vsnprintf(buffer, sizeofbuf, format, ap);
#else
	ret = vsnprintf(buffer, sizeofbuf, format, ap);
#endif
	if (ret == -1) {
		ZXIC_COMM_TRACE_ERROR("\n ZXIC %s:%d[Error:vsnprintf err], FUNCTION : %s!\n",
				      __FILE__, __LINE__, __func__);
	}
	return ret;
}
char *ic_comm_strncpy_s(char *pcDst, size_t dwMaxSize, const char *pcSrc, size_t dwCount)
{
	size_t dwIndex = 1, dwCopyNum = dwCount;
	char *pcResult = pcDst;

	ZXIC_COMM_CHECK_RC_POINT_NO_PRINT(pcDst, pcResult);
	ZXIC_COMM_CHECK_RC_POINT_NO_PRINT(pcSrc, pcResult);

	if ((dwMaxSize <= 1) || (dwMaxSize > ZXIC_COMM_MEMORY_MAX_B_SIZE) || (dwCount == 0))
		return pcResult;

	if (dwCount >= dwMaxSize)
		dwCopyNum = dwMaxSize - 1;

	if (ic_comm_getAbsValue((unsigned char *)pcDst, (const u8 *)pcSrc) < dwCopyNum)
		return pcResult;

	while ('\0' != (*pcDst++ = *pcSrc++)) {
		if (dwIndex++ >= dwCopyNum) {
			*pcDst = '\0';

			return pcResult;
		}
	}

	while (dwIndex++ <= dwCopyNum)
		*pcDst++ = '\0';

	return pcResult;
}

size_t ic_comm_getAbsValue(u8 *dest, const u8 *src)
{
	return dest > src ? (dest - src) : (src - dest);
}
u32 ic_comm_memcpy(void *dest, const void *src, size_t n)
{
	ZXIC_COMM_CHECK_POINT(dest);
	ZXIC_COMM_CHECK_POINT(src);

	if (n > 200 * 1024 * 1024)
		return ZXIC_PAR_CHK_INVALID_PARA;

	if (ic_comm_getAbsValue((u8 *)dest, (const u8 *)src) < n)
		return ZXIC_ERR;
#ifdef ZXIC_OS_WIN
	memcpy(dest, src, n);
#else
	//__memcpy_chk(dest, src, n, n);
	memcpy(dest, src, n);
#endif
	return ZXIC_OK;
}
u32 ic_comm_memcpy_s(void *dest, size_t dest_len, const void *src, size_t n)
{
	ZXIC_COMM_CHECK_POINT(dest);
	ZXIC_COMM_CHECK_POINT(src);

	if (n > 200 * 1024 * 1024)
		return ZXIC_PAR_CHK_INVALID_PARA;

	if (ic_comm_getAbsValue((u8 *)dest, (const u8 *)src) < n)
		return ZXIC_PAR_CHK_ARGIN_ERROR;

#ifdef ZXIC_OS_WIN
	if (dest_len < n)
		return ZXIC_ERR;
	memcpy(dest, src, n);
#else
	//__memcpy_chk(dest, src, n, dest_len);
	memcpy(dest, src, n);
#endif
	return ZXIC_OK;
}
char *ic_comm_strncat_s(char *pcDst, size_t dwMaxSize, const char *pcSrc, size_t dwCount)
{
	size_t dwIndex = 1, dwCopyNum = 0;
	char *pcResult = pcDst;

	ZXIC_COMM_CHECK_RC_POINT_NO_PRINT(pcDst, pcResult);
	ZXIC_COMM_CHECK_RC_POINT_NO_PRINT(pcSrc, pcResult);

	if ((dwMaxSize == 0) || (dwMaxSize > ZXIC_COMM_MEMORY_MAX_B_SIZE) || (dwCount == 0))
		return pcResult;

	if (dwCopyNum >= dwMaxSize)
		return pcResult;

	dwCopyNum = dwMaxSize - dwCopyNum;

	if (dwCount >= dwCopyNum)
		dwCopyNum = dwCopyNum - 1;
	else
		dwCopyNum = dwCount;

	if (dwCopyNum == 0)
		return pcResult;

	pcDst--;

	if (ic_comm_getAbsValue((unsigned char *)pcDst, (const unsigned char *)pcSrc) < dwCopyNum)
		return pcResult;

	while ('\0' != (*pcDst++ = *pcSrc++)) {
		if (dwIndex++ >= dwCopyNum) {
			*pcDst = '\0';

			return pcResult;
		}
	}

	while (dwIndex++ <= dwCopyNum)
		*pcDst++ = '\0';

	return pcResult;
}
size_t ic_comm_strnlen_s(const char *str, size_t MaxCount)
{
	return (str == 0) ? 0 : ZXIC_COMM_STRNLEN(str, MaxCount);
}

void ic_comm_memset_s(void *dest, size_t dmax, u8 c, size_t n)
{
	if ((dest == ZXIC_NULL) || (dmax > ZXIC_COMM_MEMORY_MAX_B_SIZE) || (n == 0) || (n > dmax)) {
		ZXIC_COMM_TRACE_ERROR("zxic_memset_s para err:ptr is null or size err.\n");
		return;
	}
	memset(dest, c, n);
}

s32 ic_comm_memcmp(void *str1, const void *str2, size_t n)
{
	if ((str1 == ZXIC_NULL) || (str2 == ZXIC_NULL) || (n > ZXIC_COMM_MEMORY_MAX_B_SIZE) ||
	    (n == 0)) {
		ZXIC_COMM_TRACE_ERROR("zxic_memcmp para err:ptr is null or size more than 200M.\n");
		return 0x7fffffff;
	}
	return memcmp(str1, str2, n);
}
#endif

u32 zxic_comm_random(void)
{
#ifdef ZXIC_OS_WIN

	return rand();
#else
	u8 buff[4] = { 0 };
	u32 ticks = 0;
	u32 random_d = 0;
	struct timespec64 tv;
	u32 result_len = 0;
	struct file *fd = NULL;
	loff_t pos = 0;

	//fd = open("/dev/urandom", O_RDONLY);
	fd = filp_open("/dev/urandom", O_RDONLY, 0);

	if (fd == NULL) {
		get_timespec64(&tv, ZXIC_NULL);
		ticks = ((tv.tv_sec & ZXIC_UINT32_MAX) + (tv.tv_nsec & ZXIC_UINT32_MAX)) &
			ZXIC_UINT32_MAX;
		random_d = ticks;
	} else {
		result_len = (kernel_read(fd, buff, ZXIC_SIZEOF(buff), &pos) & 0xFFFFFFFF);
		if (result_len != ZXIC_SIZEOF(buff)) {
			get_timespec64(&tv, ZXIC_NULL);
			ticks = ((tv.tv_sec & ZXIC_UINT32_MAX) + (tv.tv_nsec & ZXIC_UINT32_MAX)) &
				ZXIC_UINT32_MAX;
			random_d = ticks;
			filp_close(fd, NULL);
		} else {
			random_d =
				(((buff[0] << 24) & 0xff000000) | ((buff[1] << 16) & 0x00ff0000) |
				 ((buff[2] << 8) & 0x0000ff00) | (buff[3] & 0x000000ff));
			filp_close(fd, NULL);
		}
	}

	return random_d;
#endif
}
void zxic_comm_channel_max_set(u32 dev_max)
{
	g_zxic_comm_channel_max = dev_max;
}
u32 zxic_comm_channel_max_get(void)
{
	return g_zxic_comm_channel_max;
}
