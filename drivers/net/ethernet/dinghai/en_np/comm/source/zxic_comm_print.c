// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "zxic_common.h"
#include "zxic_private.h"
#include "log.h"

#if ZXIC_REAL("")
u32 g_zxic_print_level = ZXIC_TRACE_ERROR_PRINT;
u32 g_zxic_print_en = 1;
#endif

#define ZXIC_COMM_TRACE_BUFFER_SIZE (512)

#if ZXIC_REAL("")
void zxic_comm_set_print_en(u32 enable)
{
	g_zxic_print_en = enable;
}

u32 zxic_comm_get_print_en(void)
{
	return g_zxic_print_en;
}
void zxic_comm_set_print_level(u32 debug_level)
{
	g_zxic_print_level = debug_level;
}
u32 zxic_comm_get_print_level(void)
{
	return g_zxic_print_level;
}

#endif

#if ZXIC_REAL("")
void ZXIC_COMM_PRINT(const char *format, ...)
{
	va_list ap;
	char szBuffer[ZXIC_COMM_TRACE_BUFFER_SIZE];

	ZXIC_COMM_ASSERT(format);

	va_start(ap, format);
	{
		ZXIC_COMM_VSNPRINTF_S(szBuffer, ZXIC_SIZEOF(szBuffer), ZXIC_SIZEOF(szBuffer),
				      format, ap);
		if (g_zxic_print_en)
			DH_LOG_INFO(MODULE_NP, "%s", szBuffer);
	}
	va_end(ap);
}
void ZXIC_COMM_TRACE_ERROR(const char *format, ...)
{
	va_list ap;
	char szBuffer[ZXIC_COMM_TRACE_BUFFER_SIZE];

	ZXIC_COMM_ASSERT(format);

	if (zxic_comm_get_print_level() == 0 ||
	    zxic_comm_get_print_level() >= ZXIC_TRACE_INVALID_PRINT) {
		return;
	}

	va_start(ap, format);
	{
		ZXIC_COMM_VSNPRINTF_S(szBuffer, ZXIC_SIZEOF(szBuffer), ZXIC_SIZEOF(szBuffer),
				      format, ap);
		if (zxic_comm_get_print_en())
			DH_LOG_ERR(MODULE_NP, "%s", szBuffer);
	}
	va_end(ap);
}
void ZXIC_COMM_TRACE_NOTICE(const char *format, ...)
{
	va_list ap;
	char szBuffer[ZXIC_COMM_TRACE_BUFFER_SIZE];

	ZXIC_COMM_ASSERT(format);

	if (zxic_comm_get_print_level() == 0 ||
	    zxic_comm_get_print_level() >= ZXIC_TRACE_INVALID_PRINT) {
		return;
	}

	if (zxic_comm_get_print_level() >= ZXIC_TRACE_NOTICE_PRINT) {
		va_start(ap, format);
		{
			ZXIC_COMM_VSNPRINTF_S(szBuffer, ZXIC_SIZEOF(szBuffer),
					      ZXIC_SIZEOF(szBuffer), format, ap);
			if (zxic_comm_get_print_en())
				DH_LOG_INFO(MODULE_NP, "%s", szBuffer);
		}
		va_end(ap);
	}
}
void ZXIC_COMM_TRACE_INFO(const char *format, ...)
{
	va_list ap;
	char szBuffer[ZXIC_COMM_TRACE_BUFFER_SIZE];

	ZXIC_COMM_ASSERT(format);

	if (zxic_comm_get_print_level() == 0 ||
	    zxic_comm_get_print_level() >= ZXIC_TRACE_INVALID_PRINT) {
		return;
	}

	if (zxic_comm_get_print_level() >= ZXIC_TRACE_INFO_PRINT) {
		va_start(ap, format);
		{
			ZXIC_COMM_VSNPRINTF_S(szBuffer, ZXIC_SIZEOF(szBuffer),
					      ZXIC_SIZEOF(szBuffer), format, ap);
			if (zxic_comm_get_print_en())
				DH_LOG_INFO(MODULE_NP, "%s", szBuffer);
		}
		va_end(ap);
	}
}
void ZXIC_COMM_TRACE_DEBUG(const char *format, ...)
{
	va_list ap;
	char szBuffer[ZXIC_COMM_TRACE_BUFFER_SIZE];

	ZXIC_COMM_ASSERT(format);

	if (zxic_comm_get_print_level() == 0 ||
	    zxic_comm_get_print_level() >= ZXIC_TRACE_INVALID_PRINT) {
		return;
	}

	if (zxic_comm_get_print_level() >= ZXIC_TRACE_DEBUG_PRINT) {
		va_start(ap, format);
		{
			ZXIC_COMM_VSNPRINTF_S(szBuffer, ZXIC_SIZEOF(szBuffer),
					      ZXIC_SIZEOF(szBuffer), format, ap);
			if (zxic_comm_get_print_en())
				DH_LOG_DEBUG(MODULE_NP, "%s", szBuffer);
		}
		va_end(ap);
	}
}
void ZXIC_COMM_TRACE_ALL(const char *format, ...)
{
	va_list ap;
	char szBuffer[ZXIC_COMM_TRACE_BUFFER_SIZE];

	ZXIC_COMM_ASSERT(format);

	if (zxic_comm_get_print_level() == 0 ||
	    zxic_comm_get_print_level() >= ZXIC_TRACE_INVALID_PRINT) {
		return;
	}

	if (zxic_comm_get_print_level() >= ZXIC_TRACE_ALL_PRINT) {
		va_start(ap, format);
		{
			ZXIC_COMM_VSNPRINTF_S(szBuffer, ZXIC_SIZEOF(szBuffer),
					      ZXIC_SIZEOF(szBuffer), format, ap);
			if (zxic_comm_get_print_en())
				DH_LOG_DEBUG(MODULE_NP, "%s", szBuffer);
		}
		va_end(ap);
	}
}
void ZXIC_COMM_TRACE_DEV_ERROR(u32 dev_id, const char *format, ...)
{
	va_list ap;
	char szBuffer[ZXIC_COMM_TRACE_BUFFER_SIZE - 32] = { 0 };
	char devBuffer[ZXIC_COMM_TRACE_BUFFER_SIZE] = { 0 };

	ZXIC_COMM_ASSERT(format);

	if (zxic_comm_get_print_level() == 0 ||
	    zxic_comm_get_print_level() >= ZXIC_TRACE_INVALID_PRINT) {
		return;
	}

	if (zxic_comm_get_print_level() >= ZXIC_TRACE_ERROR_PRINT) {
		ZXIC_COMM_SNPRINTF_S(devBuffer, ZXIC_SIZEOF(devBuffer), ZXIC_SIZEOF(devBuffer),
				     "Dev_id[%u]_ERROR: ", dev_id);

		va_start(ap, format);
		{
			ZXIC_COMM_VSNPRINTF_S(szBuffer, ZXIC_SIZEOF(szBuffer),
					      ZXIC_SIZEOF(szBuffer), format, ap);
			ZXIC_COMM_STRNCAT_S(devBuffer, ZXIC_SIZEOF(devBuffer), szBuffer,
					    ZXIC_COMM_STRNLEN_S(szBuffer, ZXIC_SIZEOF(szBuffer)));

			if (zxic_comm_get_print_en())
				DH_LOG_ERR(MODULE_NP, "%s", devBuffer);
		}
		va_end(ap);
	}
}
void ZXIC_COMM_TRACE_DEV_NOTICE(u32 dev_id, const char *format, ...)
{
	va_list ap;
	char szBuffer[ZXIC_COMM_TRACE_BUFFER_SIZE - 32] = { 0 };
	char devBuffer[ZXIC_COMM_TRACE_BUFFER_SIZE] = { 0 };

	ZXIC_COMM_ASSERT(format);

	if (zxic_comm_get_print_level() == 0 ||
	    zxic_comm_get_print_level() >= ZXIC_TRACE_INVALID_PRINT) {
		return;
	}

	if (zxic_comm_get_print_level() >= ZXIC_TRACE_NOTICE_PRINT) {
		ZXIC_COMM_SNPRINTF_S(devBuffer, ZXIC_SIZEOF(devBuffer), ZXIC_SIZEOF(devBuffer),
				     "Dev_id[%u]_NOTICE: ", dev_id);

		va_start(ap, format);
		{
			ZXIC_COMM_VSNPRINTF_S(szBuffer, ZXIC_SIZEOF(szBuffer),
					      ZXIC_SIZEOF(szBuffer), format, ap);
			ZXIC_COMM_STRNCAT_S(devBuffer, ZXIC_SIZEOF(devBuffer), szBuffer,
					    ZXIC_COMM_STRNLEN_S(szBuffer, ZXIC_SIZEOF(szBuffer)));

			if (zxic_comm_get_print_en())
				DH_LOG_INFO(MODULE_NP, "%s", devBuffer);
		}
		va_end(ap);
	}
}
void ZXIC_COMM_TRACE_DEV_INFO(u32 dev_id, const char *format, ...)
{
	va_list ap;
	char szBuffer[ZXIC_COMM_TRACE_BUFFER_SIZE - 32] = { 0 };
	char devBuffer[ZXIC_COMM_TRACE_BUFFER_SIZE] = { 0 };

	ZXIC_COMM_ASSERT(format);

	if (zxic_comm_get_print_level() == 0 ||
	    zxic_comm_get_print_level() >= ZXIC_TRACE_INVALID_PRINT) {
		return;
	}

	if (zxic_comm_get_print_level() >= ZXIC_TRACE_INFO_PRINT) {
		ZXIC_COMM_SNPRINTF_S(devBuffer, ZXIC_SIZEOF(devBuffer), ZXIC_SIZEOF(devBuffer),
				     "Dev_id[%u]_INFO: ", dev_id);

		va_start(ap, format);
		{
			ZXIC_COMM_VSNPRINTF_S(szBuffer, ZXIC_SIZEOF(szBuffer),
					      ZXIC_SIZEOF(szBuffer), format, ap);
			ZXIC_COMM_STRNCAT_S(devBuffer, ZXIC_SIZEOF(devBuffer), szBuffer,
					    ZXIC_COMM_STRNLEN_S(szBuffer, ZXIC_SIZEOF(szBuffer)));

			if (zxic_comm_get_print_en())
				DH_LOG_INFO(MODULE_NP, "%s", devBuffer);
		}
		va_end(ap);
	}
}
void ZXIC_COMM_TRACE_DEV_DEBUG(u32 dev_id, const char *format, ...)
{
	va_list ap;
	char szBuffer[ZXIC_COMM_TRACE_BUFFER_SIZE - 32] = { 0 };
	char devBuffer[ZXIC_COMM_TRACE_BUFFER_SIZE] = { 0 };

	ZXIC_COMM_ASSERT(format);

	if (zxic_comm_get_print_level() == 0 ||
	    zxic_comm_get_print_level() >= ZXIC_TRACE_INVALID_PRINT) {
		return;
	}

	if (zxic_comm_get_print_level() >= ZXIC_TRACE_DEBUG_PRINT) {
		ZXIC_COMM_SNPRINTF_S(devBuffer, ZXIC_SIZEOF(devBuffer), ZXIC_SIZEOF(devBuffer),
				     "Dev_id[%u]_DEBUG: ", dev_id);

		va_start(ap, format);
		{
			ZXIC_COMM_VSNPRINTF_S(szBuffer, ZXIC_SIZEOF(szBuffer),
					      ZXIC_SIZEOF(szBuffer), format, ap);
			ZXIC_COMM_STRNCAT_S(devBuffer, ZXIC_SIZEOF(devBuffer), szBuffer,
					    ZXIC_COMM_STRNLEN_S(szBuffer, ZXIC_SIZEOF(szBuffer)));

			if (zxic_comm_get_print_en())
				DH_LOG_DEBUG(MODULE_NP, "%s", devBuffer);
		}
		va_end(ap);
	}
}
void ZXIC_COMM_TRACE_DEV_ALL(u32 dev_id, const char *format, ...)
{
	va_list ap;
	char szBuffer[ZXIC_COMM_TRACE_BUFFER_SIZE - 32] = { 0 };
	char devBuffer[ZXIC_COMM_TRACE_BUFFER_SIZE] = { 0 };

	ZXIC_COMM_ASSERT(format);

	if (zxic_comm_get_print_level() == 0 ||
	    zxic_comm_get_print_level() >= ZXIC_TRACE_INVALID_PRINT) {
		return;
	}

	if (zxic_comm_get_print_level() >= ZXIC_TRACE_ALL_PRINT) {
		ZXIC_COMM_SNPRINTF_S(devBuffer, ZXIC_SIZEOF(devBuffer), ZXIC_SIZEOF(devBuffer),
				     "Dev_id[%u]_ALL:", dev_id);

		va_start(ap, format);
		{
			ZXIC_COMM_VSNPRINTF_S(szBuffer, ZXIC_SIZEOF(szBuffer),
					      ZXIC_SIZEOF(szBuffer), format, ap);
			ZXIC_COMM_STRNCAT_S(devBuffer, ZXIC_SIZEOF(devBuffer), szBuffer,
					    ZXIC_COMM_STRNLEN_S(szBuffer, ZXIC_SIZEOF(szBuffer)));

			if (zxic_comm_get_print_en())
				DH_LOG_DEBUG(MODULE_NP, "%s", devBuffer);
		}
		va_end(ap);
	}
}
#endif

#if ZXIC_REAL("")

void ZXIC_COMM_DBGCNT64_PRINT(const char *name, u64 value)
{
	char temp_buff[50] = { 0 };

	if (-1 == ZXIC_COMM_SNPRINTF_S(temp_buff, 50, 50, "0x%016llx", value))
		return;

	ZXIC_COMM_PRINT("%-50s : %18s\n", name, temp_buff);
}

void ZXIC_COMM_DBGCNT32_PRINT(const char *name, u32 value)
{
	char temp_buff[50] = { 0 };

	if (-1 == ZXIC_COMM_SNPRINTF_S(temp_buff, 50, 50, "0x%08x", value))
		return;

	ZXIC_COMM_PRINT("%-50s : %18s\n", name, temp_buff);
}

void ZXIC_COMM_DBGCNT32_PAR_PRINT(const char *name, u32 parm, u32 value)
{
	char temp_buff[50] = { 0 };
	char vlaue_buff[18] = { 0 };

	if (-1 == ZXIC_COMM_SNPRINTF_S(temp_buff, 50, 50, name, parm))
		return;

	if (-1 == ZXIC_COMM_SNPRINTF_S(vlaue_buff, 18, 18, "0x%08x", value))
		return;

	ZXIC_COMM_PRINT("%-50s : %18s\n", temp_buff, vlaue_buff);
}

#endif
