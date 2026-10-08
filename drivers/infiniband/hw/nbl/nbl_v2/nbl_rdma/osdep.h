/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/*
 * Copyright (c) 2021 nebula-matrix Limited.
 */
#ifndef NBL_OSDEP_H
#define NBL_OSDEP_H

/* helper macros */
#define __nbldv_nullp(typ) ((struct nbl_ifc_##typ##_bits *)0)
#define __nbldv_bit_sz(typ, fld) sizeof(__nbldv_nullp(typ)->fld)
#define __nbldv_bit_off(typ, fld) (offsetof(struct nbl_ifc_##typ##_bits, fld))
#define __nbldv_16_off(typ, fld) (__nbldv_bit_off(typ, fld) / 16)
#define __nbldv_dw_off(typ, fld) (__nbldv_bit_off(typ, fld) / 32)
#define __nbldv_64_off(typ, fld) (__nbldv_bit_off(typ, fld) / 64)
#define __nbldv_16_bit_off(typ, fld) \
	(16 - __nbldv_bit_sz(typ, fld) - (__nbldv_bit_off(typ, fld) & 0xf))
#define __nbldv_dw_bit_off(typ, fld) \
	(32 - __nbldv_bit_sz(typ, fld) - (__nbldv_bit_off(typ, fld) & 0x1f))
#define __nbldv_mask(typ, fld) ((u32)((1ull << __nbldv_bit_sz(typ, fld)) - 1))
#define __nbldv_dw_mask(typ, fld) \
	(__nbldv_mask(typ, fld) << __nbldv_dw_bit_off(typ, fld))
#define __nbldv_mask16(typ, fld) \
	((u16)((1ull << __nbldv_bit_sz(typ, fld)) - 1))
#define __nbldv_16_mask(typ, fld) \
	(__nbldv_mask16(typ, fld) << __nbldv_16_bit_off(typ, fld))
#define __nbldv_st_sz_bits(typ) sizeof(struct nbl_ifc_##typ##_bits)

#define NBLDV_FLD_SZ_BYTES(typ, fld) (__nbldv_bit_sz(typ, fld) / 8)
#define NBLDV_ST_SZ_BYTES(typ) (sizeof(struct nbl_ifc_##typ##_bits) / 8)
#define NBLDV_ST_SZ_DW(typ) (sizeof(struct nbl_ifc_##typ##_bits) / 32)
#define NBLDV_ST_SZ_QW(typ) (sizeof(struct nbl_ifc_##typ##_bits) / 64)
#define NBLDV_UN_SZ_BYTES(typ) (sizeof(union nbl_ifc_##typ##_bits) / 8)
#define NBLDV_UN_SZ_DW(typ) (sizeof(union nbl_ifc_##typ##_bits) / 32)
#define NBLDV_BYTE_OFF(typ, fld) (__nbldv_bit_off(typ, fld) / 8)
#define NBLDV_ADDR_OF(typ, p, fld) \
	((void *)((uint8_t *)(p) + NBLDV_BYTE_OFF(typ, fld)))

/* insert a value to a struct */
#define NBLDV_SET(typ, p, fld, v) do { \
	u32 _v = v; \
	BUILD_BUG_ON(__nbldv_st_sz_bits(typ) % 32);             \
	*((__be32 *)(p) + __nbldv_dw_off(typ, fld)) = \
	cpu_to_be32((be32_to_cpu(*((__be32 *)(p) + __nbldv_dw_off(typ, fld))) & \
		     (~__nbldv_dw_mask(typ, fld))) | (((_v) & __nbldv_mask(typ, fld)) \
		     << __nbldv_dw_bit_off(typ, fld))); \
} while (0)

#define NBLDV_GET(typ, p, fld) ((be32_to_cpu(*((__be32 *)(p) +\
__nbldv_dw_off(typ, fld))) >> __nbldv_dw_bit_off(typ, fld)) & \
__nbldv_mask(typ, fld))

struct nbl_dma_mem {
	void *va;
	dma_addr_t pa;
	u32 size;
} __packed;

#endif /* NBL_OSDEP_H */
