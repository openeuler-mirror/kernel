/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPFC_UTILS_H
#define SPFC_UTILS_H

#include "unf_type.h"
#include "unf_log.h"

#define SPFC_ZERO (0)

#define SPFC_BIT(n) (0x1UL << (n))
#define SPFC_BIT_0 SPFC_BIT(0)
#define SPFC_BIT_1 SPFC_BIT(1)
#define SPFC_BIT_2 SPFC_BIT(2)
#define SPFC_BIT_3 SPFC_BIT(3)
#define SPFC_BIT_4 SPFC_BIT(4)
#define SPFC_BIT_5 SPFC_BIT(5)
#define SPFC_BIT_6 SPFC_BIT(6)
#define SPFC_BIT_7 SPFC_BIT(7)
#define SPFC_BIT_8 SPFC_BIT(8)
#define SPFC_BIT_9 SPFC_BIT(9)
#define SPFC_BIT_10 SPFC_BIT(10)
#define SPFC_BIT_11 SPFC_BIT(11)
#define SPFC_BIT_12 SPFC_BIT(12)
#define SPFC_BIT_13 SPFC_BIT(13)
#define SPFC_BIT_14 SPFC_BIT(14)
#define SPFC_BIT_15 SPFC_BIT(15)
#define SPFC_BIT_16 SPFC_BIT(16)
#define SPFC_BIT_17 SPFC_BIT(17)
#define SPFC_BIT_18 SPFC_BIT(18)
#define SPFC_BIT_19 SPFC_BIT(19)
#define SPFC_BIT_20 SPFC_BIT(20)
#define SPFC_BIT_21 SPFC_BIT(21)
#define SPFC_BIT_22 SPFC_BIT(22)
#define SPFC_BIT_23 SPFC_BIT(23)
#define SPFC_BIT_24 SPFC_BIT(24)
#define SPFC_BIT_25 SPFC_BIT(25)
#define SPFC_BIT_26 SPFC_BIT(26)
#define SPFC_BIT_27 SPFC_BIT(27)
#define SPFC_BIT_28 SPFC_BIT(28)
#define SPFC_BIT_29 SPFC_BIT(29)
#define SPFC_BIT_30 SPFC_BIT(30)
#define SPFC_BIT_31 SPFC_BIT(31)

#define SPFC_GET_BITS(data, mask) ((data) & (mask))   /* Obtains the bit */
#define SPFC_SET_BITS(data, mask) ((data) |= (mask))  /* set the bit */
#define SPFC_CLR_BITS(data, mask) ((data) &= ~(mask)) /* clear the bit */

#define SPFC_LSB(x) ((u8)(x))
#define SPFC_MSB(x) ((u8)((u16)(x) >> 8))

#define SPFC_LSW(x) ((u16)(x))
#define SPFC_MSW(x) ((u16)((u32)(x) >> 16))

#define SPFC_LSD(x) ((u32)((u64)(x)))
#define SPFC_MSD(x) ((u32)((((u64)(x)) >> 16) >> 16))

#define SPFC_BYTES_TO_QW_NUM(x) ((x) >> 3)
#define SPFC_BYTES_TO_DW_NUM(x) ((x) >> 2)

#define UNF_GET_SHIFTMASK(__src, __shift, __mask) (((__src) & (__mask)) >> (__shift))
#define UNF_FC_SET_SHIFTMASK(__des, __val, __shift, __mask) \
	((__des) = (((__des) & ~(__mask)) | (((__val) << (__shift)) & (__mask))))

/* R_CTL */
#define UNF_FC_HEADER_RCTL_MASK (0xFF000000)
#define UNF_FC_HEADER_RCTL_SHIFT (24)
#define UNF_FC_HEADER_RCTL_DWORD (0)
#define UNF_GET_FC_HEADER_RCTL(__pfcheader)                           \
	UNF_GET_SHIFTMASK(((u32 *)(void *)(__pfcheader))[UNF_FC_HEADER_RCTL_DWORD], \
	    UNF_FC_HEADER_RCTL_SHIFT, UNF_FC_HEADER_RCTL_MASK)

#define UNF_SET_FC_HEADER_RCTL(__pfcheader, __val)                \
	do {                                                          \
		UNF_FC_SET_SHIFTMASK(((u32 *)(void *)(__pfcheader)[UNF_FC_HEADER_RCTL_DWORD],  \
		__val, UNF_FC_HEADER_RCTL_SHIFT, UNF_FC_HEADER_RCTL_MASK) \
	} while (0)

/* PRLI PARAM 3 */
#define SPFC_PRLI_PARAM_WXFER_ENABLE_MASK (0x00000001)
#define SPFC_PRLI_PARAM_WXFER_ENABLE_SHIFT (0)
#define SPFC_PRLI_PARAM_WXFER_DWORD (3)
#define SPFC_GET_PRLI_PARAM_WXFER(__pfcheader)                           \
	UNF_GET_SHIFTMASK(((u32 *)(void *)(__pfcheader))[SPFC_PRLI_PARAM_WXFER_DWORD], \
	    SPFC_PRLI_PARAM_WXFER_ENABLE_SHIFT,                          \
	    SPFC_PRLI_PARAM_WXFER_ENABLE_MASK)

#define SPFC_PRLI_PARAM_CONF_ENABLE_MASK (0x00000080)
#define SPFC_PRLI_PARAM_CONF_ENABLE_SHIFT (7)
#define SPFC_PRLI_PARAM_CONF_DWORD (3)
#define SPFC_GET_PRLI_PARAM_CONF(__pfcheader)                           \
	UNF_GET_SHIFTMASK(((u32 *)(void *)(__pfcheader))[SPFC_PRLI_PARAM_CONF_DWORD], \
	    SPFC_PRLI_PARAM_CONF_ENABLE_SHIFT,                          \
	    SPFC_PRLI_PARAM_CONF_ENABLE_MASK)

#define SPFC_PRLI_PARAM_REC_ENABLE_MASK (0x00000400)
#define SPFC_PRLI_PARAM_REC_ENABLE_SHIFT (10)
#define SPFC_PRLI_PARAM_CONF_REC (3)
#define SPFC_GET_PRLI_PARAM_REC(__pfcheader)                          \
	UNF_GET_SHIFTMASK(((u32 *)(void *)(__pfcheader))[SPFC_PRLI_PARAM_CONF_REC], \
	    SPFC_PRLI_PARAM_REC_ENABLE_SHIFT, SPFC_PRLI_PARAM_REC_ENABLE_MASK)

#define SPFC_FUNCTION_ENTER                   \
	FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_ALL, \
		     "%s Enter.", __func__)
#define SPFC_FUNCTION_RETURN                   \
	FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_ALL,  \
		     "%s Return.", __func__)

#define SPFC_SPIN_LOCK_IRQSAVE(interrupt, hw_adapt_lock, flags)              \
	do {                                                                 \
		if ((interrupt) == false) {                                  \
			spin_lock_irqsave(&(hw_adapt_lock), flags);          \
		}                                                            \
	} while (0)

#define SPFC_SPIN_UNLOCK_IRQRESTORE(interrupt, hw_adapt_lock, flags)    \
	do {                                                              \
		if ((interrupt) == false) {                               \
			spin_unlock_irqrestore(&(hw_adapt_lock), flags);  \
		}                                                         \
	} while (0)

#define FC_CHECK_VALID(condition, fail_do)                              \
	do {                                                            \
		if (unlikely(!(condition))) {                           \
			FC_DRV_PRINT(UNF_LOG_REG_ATT,  \
				     UNF_ERR, "Para check(%s) invalid", \
				     #condition);                       \
			fail_do;                                        \
		}                                                       \
	} while (0)

#define RETURN_ERROR_S32 (-1)
#define UNF_RETURN_ERROR_S32 (-1)

enum SPFC_LOG_CTRL_E {
	SPFC_LOG_ALL = 0,
	SPFC_LOG_SCQE_RX,
	SPFC_LOG_ELS_TX,
	SPFC_LOG_ELS_RX,
	SPFC_LOG_GS_TX,
	SPFC_LOG_GS_RX,
	SPFC_LOG_BLS_TX,
	SPFC_LOG_BLS_RX,
	SPFC_LOG_FCP_TX,
	SPFC_LOG_FCP_RX,
	SPFC_LOG_SESS_TX,
	SPFC_LOG_SESS_RX,
	SPFC_LOG_DIF_TX,
	SPFC_LOG_DIF_RX
};

extern u32 spfc_log_en;
#define SPFC_LOG_EN(hba, log_ctrl) (spfc_log_en + (log_ctrl))

enum SPFC_HBA_ERR_STAT_E {
	SPFC_STAT_CTXT_FLUSH_DONE = 0,
	SPFC_STAT_SQ_WAIT_EMPTY,
	SPFC_STAT_LAST_GS_SCQE,
	SPFC_STAT_SQ_POOL_EMPTY,
	SPFC_STAT_PARENT_IO_FLUSHED,
	SPFC_STAT_ROOT_IO_FLUSHED, /* 5 */
	SPFC_STAT_ROOT_SQ_FULL,
	SPFC_STAT_ELS_RSP_EXCH_REUSE,
	SPFC_STAT_GS_RSP_EXCH_REUSE,
	SPFC_STAT_SQ_IO_BUFFER_CLEARED,
	SPFC_STAT_PARENT_SQ_NOT_OFFLOADED, /* 10 */
	SPFC_STAT_PARENT_SQ_QUEUE_DELAYED_WORK,
	SPFC_STAT_PARENT_SQ_INVALID_CACHED_ID,
	SPFC_HBA_STAT_BUTT
};

#define SPFC_DWORD_BYTE (4)
#define SPFC_QWORD_BYTE (8)
#define SPFC_SHIFT_TO_U64(x) ((x) >> 3)
#define SPFC_SHIFT_TO_U32(x) ((x) >> 2)

void spfc_cpu_to_big64(void *addr, u32 size);
void spfc_big_to_cpu64(void *addr, u32 size);
void spfc_cpu_to_big32(void *addr, u32 size);
void spfc_big_to_cpu32(void *addr, u32 size);
void spfc_cpu_to_be24(u8 *data, u32 value);
u32 spfc_big_to_cpu24(u8 *data);

void spfc_print_buff(u32 dbg_level, void *buff, u32 size);

u32 spfc_log2n(u32 val);

static inline void spfc_swap_16_in_32(u32 *paddr, u32 length)
{
	u32 i;

	for (i = 0; i < length; i++) {
		paddr[i] =
		    ((((paddr[i]) & UNF_MASK_BIT_31_16) >> UNF_SHIFT_16) |
		     (((paddr[i]) & UNF_MASK_BIT_15_0) << UNF_SHIFT_16));
	}
}

#endif /* __SPFC_UTILS_H__ */
