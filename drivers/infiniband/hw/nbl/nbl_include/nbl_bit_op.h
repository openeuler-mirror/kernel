/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_BIT_OP_H
#define NBL_BIT_OP_H

#include <linux/bitfield.h>
#include <linux/types.h>

/* Field Location Related, must use 64/32/16B as unit.
 * byteoffset << 16 + high position << 8 + low position.
 * bo for byte offset, h/l for high/low position.
 */
#define FIELD_LOC(bo, h, l) (((bo) << 16) + ((h) << 8) + (l))
#define FIELD_BO(f) ((f) >> 16)
#define FIELD_H(f) (((f) >> 8) & 0xff)
#define FIELD_L(f) ((f) & 0xff)

#define nbl_32bit_clear(ptr, field)                                            \
	({                                                                     \
		__be32 *clr_p = (ptr);                                           \
		clr_p[(FIELD_BO(field)) >> 2] &= ~(                            \
			cpu_to_be32(GENMASK_ULL(FIELD_H(field), FIELD_L(field)))); \
	})

#define nbl_32bit_enable(ptr, field)                                           \
	({                                                                     \
		__be32 *en_p = (ptr);                                          \
		en_p[(FIELD_BO(field)) >> 2] |= (cpu_to_be32(                      \
			GENMASK_ULL(FIELD_H(field), FIELD_L(field))));         \
	})

#define nbl_32bit_write_bool(ptr, field, val)                                  \
	({                                                                     \
		(val) ? nbl_32bit_enable(ptr, field) :                         \
			nbl_32bit_clear(ptr, field);                           \
	})

#define nbl_32bit_write(ptr, field, val)                                       \
	({                                                                     \
		const uint32_t _val = (val);                                     \
		__be32 *write_p = (ptr);                                         \
		nbl_32bit_clear(ptr, field);                                   \
		write_p[(FIELD_BO(field)) >> 2] |= (cpu_to_be32(FIELD_PREP(        \
			GENMASK_ULL(FIELD_H(field), FIELD_L(field)), _val)));  \
	})

#define nbl_64bit_clear(ptr, field)                                            \
	({                                                                     \
		__be64 *clr_p = (ptr);                                           \
		clr_p[(FIELD_BO(field)) >> 3] &= ~(                            \
			cpu_to_be64(GENMASK_ULL(FIELD_H(field), FIELD_L(field)))); \
	})

#define nbl_64bit_enable(ptr, field)                                           \
	({                                                                     \
		__be64 *en_p = (ptr);                                          \
		en_p[(FIELD_BO(field)) >> 3] |= (cpu_to_be64(                      \
			GENMASK_ULL(FIELD_H(field), FIELD_L(field))));         \
	})

#define nbl_64bit_write_bool(ptr, field, val)                                  \
	({                                                                     \
		(val) ? nbl_64bit_enable(ptr, field) :                         \
			nbl_64bit_clear(ptr, field);                           \
	})

#define nbl_64bit_write(ptr, field, val)                                       \
	({                                                                     \
		const uint64_t _val = (val);                                     \
		__be64 *write_p = (ptr);                                         \
		nbl_64bit_clear(ptr, field);                                   \
		write_p[(FIELD_BO(field)) >> 3] |= (cpu_to_be64(FIELD_PREP(        \
			GENMASK_ULL(FIELD_H(field), FIELD_L(field)), _val)));  \
	})

#define nbl_32bit_read(ptr, field)                                             \
	({                                                                     \
		const __be32 *read_p = (ptr);                                    \
		FIELD_GET(GENMASK_ULL(FIELD_H(field), FIELD_L(field)),         \
			  be32_to_cpu(read_p[(FIELD_BO(field)) >> 2]));            \
	})

#define nbl_64bit_read(ptr, field)                                             \
	({                                                                     \
		const __be64 *read_p = (ptr);                                    \
		FIELD_GET(GENMASK_ULL(FIELD_H(field), FIELD_L(field)),         \
			  be64_to_cpu(read_p[(FIELD_BO(field)) >> 3]));            \
	})

#endif /* NBL_BIT_OP_H */
