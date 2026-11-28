/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_compat_overflow.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __LINUX_OVERFLOW_H
#define __LINUX_OVERFLOW_H

#include <linux/compiler.h>
#include <linux/limits.h>
#include <linux/const.h>

#include <linux/types.h>
#ifndef SIZE_MAX
#define SIZE_MAX (~(size_t)0)
#endif

#define _kc_is_signed_type(type)       (((type)(-1)) < (type)1)
#define __type_half_max(type) ((type)1 << (8 * sizeof(type) - 1 - _kc_is_signed_type(type)))
#define type_max(T) ((T)((__type_half_max(T) - 1) + __type_half_max(T)))
#define type_min(T) ((T)((T) - type_max(T) - (T)1))

#define is_non_negative(a) ((a) > 0 || (a) == 0)
#define is_negative(a) (!(is_non_negative(a)))

#ifdef COMPILER_HAS_GENERIC_BUILTIN_OVERFLOW
static inline bool __must_check __must_check_overflow(bool overflow)
{
	return unlikely(overflow);
}

#ifndef check_add_overflow
#define check_add_overflow(a, b, d)		\
	__must_check_overflow(__builtin_add_overflow(a, b, d))
#endif

#ifndef check_sub_overflow
#define check_sub_overflow(a, b, d)		\
	__must_check_overflow(__builtin_sub_overflow(a, b, d))
#endif

#ifndef check_mul_overflow
#define check_mul_overflow(a, b, d)		\
	__must_check_overflow(__builtin_mul_overflow(a, b, d))
#endif

#else
#ifndef __CHECKER__

#define __unsigned_add_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void)(&__a == &__b);			\
	(void)(&__a == __d);			\
	*__d = __a + __b;			\
	*__d < __a;				\
})
#define __unsigned_sub_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void)(&__a == &__b);			\
	(void)(&__a == __d);			\
	*__d = __a - __b;			\
	__a < __b;				\
})
#define __unsigned_mul_overflow(a, b, d) ({		\
	typeof(a) __a = (a);				\
	typeof(b) __b = (b);				\
	typeof(d) __d = (d);				\
	(void)(&__a == &__b);				\
	(void)(&__a == __d);				\
	*__d = __a * __b;				\
	__builtin_constant_p(__b) ?			\
	  __b > 0 && __a > type_max(typeof(__a)) / __b : \
	  __a > 0 && __b > type_max(typeof(__b)) / __a;	 \
})

#define __signed_add_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void)(&__a == &__b);			\
	(void)(&__a == __d);			\
	*__d = (u64)__a + (u64)__b;		\
	(((~(__a ^ __b)) & (*__d ^ __a))	\
		& type_min(typeof(__a))) != 0;	\
})

#define __signed_sub_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void)(&__a == &__b);			\
	(void)(&__a == __d);			\
	*__d = (u64)__a - (u64)__b;		\
	((((__a ^ __b)) & (*__d ^ __a))		\
		& type_min(typeof(__a))) != 0;	\
})

#define __signed_mul_overflow(a, b, d) ({				\
	typeof(a) __a = (a);						\
	typeof(b) __b = (b);						\
	typeof(d) __d = (d);						\
	typeof(a) __tmax = type_max(typeof(a));				\
	typeof(a) __tmin = type_min(typeof(a));				\
	(void)(&__a == &__b);						\
	(void)(&__a == __d);						\
	*__d = (u64)__a * (u64)__b;					\
	(__b > 0   && (__a > __tmax / __b || __a < __tmin / __b)) ||	\
	(__b < (typeof(__b))-1  && (__a > __tmin / __b || __a < __tmax / __b)) || \
	(__b == (typeof(__b))-1 && __a == __tmin);			\
})

#ifndef check_add_overflow
#define check_add_overflow(a, b, d)					\
	__builtin_choose_expr(_kc_is_signed_type(typeof(a)),		\
			__signed_add_overflow(a, b, d),			\
			__unsigned_add_overflow(a, b, d))
#endif

#ifndef check_sub_overflow
#define check_sub_overflow(a, b, d)					\
	__builtin_choose_expr(_kc_is_signed_type(typeof(a)),		\
			__signed_sub_overflow(a, b, d),			\
			__unsigned_sub_overflow(a, b, d))
#endif

#ifndef check_mul_overflow
#define check_mul_overflow(a, b, d)					\
	__builtin_choose_expr(_kc_is_signed_type(typeof(a)),		\
			__signed_mul_overflow(a, b, d),			\
			__unsigned_mul_overflow(a, b, d))
#endif

#endif
#endif

#define check_shl_overflow(a, s, d) ({					\
	typeof(a) _a = a;						\
	typeof(s) _s = s;						\
	typeof(d) _d = d;						\
	u64 _a_full = _a;						\
	unsigned int _to_shift =					\
		_s >= 0 && _s < 8 * sizeof(*d) ? _s : 0;		\
	*_d = (_a_full << _to_shift);					\
	(_to_shift != _s || *_d < 0 || _a < 0 ||			\
		(*_d >> _to_shift) != _a);				\
})

#define __overflows_type_constexpr(x, T) (\
	is_unsigned_type(typeof(x)) ? \
		(x) > type_max(typeof(T)) : \
	is_unsigned_type(typeof(T)) ? \
		(x) < 0 || (x) > type_max(typeof(T)) : \
	(x) < type_min(typeof(T)) || (x) > type_max(typeof(T)))

#define __overflows_type(x, T)		({	\
	typeof(T) v = 0;			\
	check_add_overflow((x), v, &v);		\
})

#define overflows_type(n, T)					\
	__builtin_choose_expr(__is_constexpr(n),		\
			      __overflows_type_constexpr(n, T),	\
			      __overflows_type(n, T))

#define castable_to_type(n, T)						\
	__builtin_choose_expr(__is_constexpr(n),			\
			      !__overflows_type_constexpr(n, T),	\
			      __same_type(n, T))

#ifndef SXE2_ETH_OFED_SIZE_MUL
static inline size_t __must_check size_mul(size_t factor1, size_t factor2)
{
	size_t bytes;

	if (check_mul_overflow(factor1, factor2, &bytes))
		return SIZE_MAX;

	return bytes;
}
#endif

static inline size_t __must_check size_add(size_t addend1, size_t addend2)
{
	size_t bytes;

	if (check_add_overflow(addend1, addend2, &bytes))
		return SIZE_MAX;

	return bytes;
}

static inline size_t __must_check size_sub(size_t minuend, size_t subtrahend)
{
	size_t bytes;

	if (minuend == SIZE_MAX || subtrahend == SIZE_MAX ||
	    check_sub_overflow(minuend, subtrahend, &bytes))
		return SIZE_MAX;

	return bytes;
}

#define array_size(a, b)	size_mul(a, b)

#define array3_size(a, b, c)	size_mul(size_mul(a, b), c)

#define flex_array_size(p, member, count)				\
	__builtin_choose_expr(__is_constexpr(count),			\
		(count) * sizeof(*(p)->member) + __must_be_array((p)->member),	\
		size_mul(count, sizeof(*(p)->member) + __must_be_array((p)->member)))

#define struct_size(p, member, count)					\
	__builtin_choose_expr(__is_constexpr(count),			\
		sizeof(*(p)) + flex_array_size(p, member, count),	\
		size_add(sizeof(*(p)), flex_array_size(p, member, count)))

#define struct_size_t(type, member, count)					\
	struct_size((type *)NULL, member, count)

#define _DEFINE_FLEX(type, name, member, count, initializer)			\
	_Static_assert(__builtin_constant_p(count),				\
		       "onstack flex array members require compile-time const count"); \
	union {									\
		u8 bytes[struct_size_t(type, member, count)];			\
		type obj;							\
	} name##_u initializer;							\
	type *name = (type *)&name##_u

#define DEFINE_RAW_FLEX(type, name, member, count)	\
	_DEFINE_FLEX(type, name, member, count, = {})

#define DEFINE_FLEX(type, name, member, count)			\
	_DEFINE_FLEX(type, name, member, count, = {})

#endif
