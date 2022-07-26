/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 *
 * Derived from MIPS:
 * Copyright (C) 1996, 1997, 1998, 1999, 2000, 03, 04 by Ralf Baechle
 * Copyright (C) 1999, 2000 Silicon Graphics, Inc.
 * Copyright (C) 2007  Maciej W. Rozycki
 * Copyright (C) 2014, Imagination Technologies Ltd.
 */
#ifndef _ASM_UACCESS_H
#define _ASM_UACCESS_H

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/extable.h>
#include <asm/pgtable.h>
#include <asm-generic/extable.h>

extern u64 __ua_limit;

#define __UA_ADDR	".dword"
#define __UA_LA		"la.abs"
#define __UA_LIMIT	__ua_limit

/*
 * Is a address valid? This does a straightforward calculation rather
 * than tests.
 *
 * Address valid if:
 *  - "addr" doesn't have any high-bits set
 *  - AND "size" doesn't have any high-bits set
 *  - AND "addr+size" doesn't have any high-bits set
 *  - OR we are in kernel mode.
 *
 * __ua_size() is a trick to avoid runtime checking of positive constant
 * sizes; for those we already know at compile time that the size is ok.
 */
#define __ua_size(size)							\
	((__builtin_constant_p(size) && (signed long) (size) > 0) ? 0 : (size))

/*
 * access_ok: - Checks if a user space pointer is valid
 * @addr: User space pointer to start of block to check
 * @size: Size of block to check
 *
 * Context: User context only. This function may sleep if pagefaults are
 *          enabled.
 *
 * Checks if a pointer to a block of memory in user space is valid.
 *
 * Returns true (nonzero) if the memory block may be valid, false (zero)
 * if it is definitely invalid.
 *
 * Note that, depending on architecture, this function probably just
 * checks that the pointer is in the user space range - after calling
 * this function, memory access functions may still return -EFAULT.
 */

static inline int __access_ok(const void __user *p, unsigned long size)
{
	unsigned long addr = (unsigned long)p;
	return (__UA_LIMIT & (addr | (addr + size) | __ua_size(size))) == 0;
}

#define access_ok(addr, size)					\
	likely(__access_ok((addr), (size)))

/*
 * get_user: - Get a simple variable from user space.
 * @x:	 Variable to store result.
 * @ptr: Source address, in user space.
 *
 * Context: User context only. This function may sleep if pagefaults are
 *          enabled.
 *
 * This macro copies a single simple variable from user space to kernel
 * space.  It supports simple types like char and int, but not larger
 * data types like structures or arrays.
 *
 * @ptr must have pointer-to-simple-variable type, and the result of
 * dereferencing @ptr must be assignable to @x without a cast.
 *
 * Returns zero on success, or -EFAULT on error.
 * On error, the variable @x is set to zero.
 */
#define get_user(x, ptr) \
({									\
	const __typeof__(*(ptr)) __user *__p = (ptr);			\
									\
	might_fault();							\
	access_ok(__p, sizeof(*__p)) ? __get_user((x), __p) :		\
				       ((x) = 0, -EFAULT);		\
})

/*
 * put_user: - Write a simple value into user space.
 * @x:	 Value to copy to user space.
 * @ptr: Destination address, in user space.
 *
 * Context: User context only. This function may sleep if pagefaults are
 *          enabled.
 *
 * This macro copies a single simple value from kernel space to user
 * space.  It supports simple types like char and int, but not larger
 * data types like structures or arrays.
 *
 * @ptr must have pointer-to-simple-variable type, and @x must be assignable
 * to the result of dereferencing @ptr.
 *
 * Returns zero on success, or -EFAULT on error.
 */
#define put_user(x, ptr) \
({									\
	__typeof__(*(ptr)) __user *__p = (ptr);				\
									\
	might_fault();							\
	access_ok(__p, sizeof(*__p)) ? __put_user((x), __p) : -EFAULT;	\
})

/*
 * __get_user: - Get a simple variable from user space, with less checking.
 * @x:	 Variable to store result.
 * @ptr: Source address, in user space.
 *
 * Context: User context only. This function may sleep if pagefaults are
 *          enabled.
 *
 * This macro copies a single simple variable from user space to kernel
 * space.  It supports simple types like char and int, but not larger
 * data types like structures or arrays.
 *
 * @ptr must have pointer-to-simple-variable type, and the result of
 * dereferencing @ptr must be assignable to @x without a cast.
 *
 * Caller must check the pointer with access_ok() before calling this
 * function.
 *
 * Returns zero on success, or -EFAULT on error.
 * On error, the variable @x is set to zero.
 */
#define __get_user(x, ptr) \
({									\
	int __gu_err = 0;						\
									\
	__chk_user_ptr(ptr);						\
	__get_user_common((x), sizeof(*(ptr)), ptr);			\
	__gu_err;							\
})

/*
 * __put_user: - Write a simple value into user space, with less checking.
 * @x:	 Value to copy to user space.
 * @ptr: Destination address, in user space.
 *
 * Context: User context only. This function may sleep if pagefaults are
 *          enabled.
 *
 * This macro copies a single simple value from kernel space to user
 * space.  It supports simple types like char and int, but not larger
 * data types like structures or arrays.
 *
 * @ptr must have pointer-to-simple-variable type, and @x must be assignable
 * to the result of dereferencing @ptr.
 *
 * Caller must check the pointer with access_ok() before calling this
 * function.
 *
 * Returns zero on success, or -EFAULT on error.
 */
#define __put_user(x, ptr) \
({									\
	int __pu_err = 0;						\
	__typeof__(*(ptr)) __pu_val;					\
									\
	__pu_val = (x);							\
	__chk_user_ptr(ptr);						\
	__put_user_common(ptr, sizeof(*(ptr)));				\
	__pu_err;							\
})

struct __large_struct { unsigned long buf[100]; };
#define __m(x) (*(struct __large_struct __user *)(x))

#define __get_user_common(val, size, ptr)				\
do {									\
	switch (size) {							\
	case 1: __get_data_asm(val, "ld.b", ptr); break;		\
	case 2: __get_data_asm(val, "ld.h", ptr); break;		\
	case 4: __get_data_asm(val, "ld.w", ptr); break;		\
	case 8: __get_data_asm(val, "ld.d", ptr); break;		\
	default: BUILD_BUG(); break;					\
	}								\
} while (0)

#define __get_kernel_common(val, size, ptr) __get_user_common(val, size, ptr)

#define __get_data_asm(val, insn, ptr)					\
{									\
	long __gu_tmp;							\
									\
	__asm__ __volatile__(						\
	"1:	" insn "	%1, %2				\n"	\
	"2:							\n"	\
	"	.section .fixup,\"ax\"				\n"	\
	"3:	li.w	%0, %3					\n"	\
	"	move	%1, $zero				\n"	\
	"	b	2b					\n"	\
	"	.previous					\n"	\
	"	.section __ex_table,\"a\"			\n"	\
	"	"__UA_ADDR "\t1b, 3b				\n"	\
	"	.previous					\n"	\
	: "+r" (__gu_err), "=r" (__gu_tmp)				\
	: "m" (__m(ptr)), "i" (-EFAULT));				\
									\
	(val) = (__typeof__(*(ptr))) __gu_tmp;				\
}

#define __put_user_common(ptr, size)					\
do {									\
	switch (size) {							\
	case 1: __put_data_asm("st.b", ptr); break;			\
	case 2: __put_data_asm("st.h", ptr); break;			\
	case 4: __put_data_asm("st.w", ptr); break;			\
	case 8: __put_data_asm("st.d", ptr); break;			\
	default: BUILD_BUG(); break;					\
	}								\
} while (0)

#define __put_kernel_common(ptr, size) __put_user_common(ptr, size)

#define __put_data_asm(insn, ptr)					\
{									\
	__asm__ __volatile__(						\
	"1:	" insn "	%z2, %1		# __put_user_asm\n"	\
	"2:							\n"	\
	"	.section	.fixup,\"ax\"			\n"	\
	"3:	li.w	%0, %3					\n"	\
	"	b	2b					\n"	\
	"	.previous					\n"	\
	"	.section	__ex_table,\"a\"		\n"	\
	"	" __UA_ADDR "	1b, 3b				\n"	\
	"	.previous					\n"	\
	: "+r" (__pu_err), "=m" (__m(ptr))				\
	: "Jr" (__pu_val), "i" (-EFAULT));				\
}

#define HAVE_GET_KERNEL_NOFAULT

#define __get_kernel_nofault(dst, src, type, err_label)			\
do {									\
	int __gu_err = 0;						\
									\
	__get_kernel_common(*((type *)(dst)), sizeof(type),		\
			    (__force type *)(src));			\
	if (unlikely(__gu_err))						\
		goto err_label;						\
} while (0)

#define __put_kernel_nofault(dst, src, type, err_label)			\
do {									\
	type __pu_val;							\
	int __pu_err = 0;						\
									\
	__pu_val = *(__force type *)(src);				\
	__put_kernel_common(((type *)(dst)), sizeof(type));		\
	if (unlikely(__pu_err))						\
		goto err_label;						\
} while (0)

extern unsigned long __copy_user(void *to, const void *from, __kernel_size_t n);

static inline unsigned long __must_check
raw_copy_from_user(void *to, const void __user *from, unsigned long n)
{
	return __copy_user(to, from, n);
}

static inline unsigned long __must_check
raw_copy_to_user(void __user *to, const void *from, unsigned long n)
{
	return __copy_user(to, from, n);
}

#define INLINE_COPY_FROM_USER
#define INLINE_COPY_TO_USER

/*
 * __clear_user: - Zero a block of memory in user space, with less checking.
 * @addr: Destination address, in user space.
 * @size: Number of bytes to zero.
 *
 * Zero a block of memory in user space.  Caller must check
 * the specified block with access_ok() before calling this function.
 *
 * Returns number of bytes that could not be cleared.
 * On success, this will be zero.
 */
extern unsigned long __clear_user(void __user *addr, __kernel_size_t size);

#define clear_user(addr, n)						\
({									\
	void __user *__cl_addr = (addr);				\
	unsigned long __cl_size = (n);					\
	if (__cl_size && access_ok(__cl_addr, __cl_size))		\
		__cl_size = __clear_user(__cl_addr, __cl_size);		\
	__cl_size;							\
})

extern long __strncpy_from_user(char *to, const char __user *from, long len);

/*
 * strncpy_from_user: - Copy a NUL terminated string from userspace.
 * @to:   Destination address, in kernel space.  This buffer must be at
 *	  least @len bytes long.
 * @from: Source address, in user space.
 * @len:  Maximum number of bytes to copy, including the trailing NUL.
 *
 * Copies a NUL-terminated string from userspace to kernel space.
 *
 * On success, returns the length of the string (not including the trailing
 * NUL).
 *
 * If access to userspace fails, returns -EFAULT (some data may have been
 * copied).
 *
 * If @len is smaller than the length of the string, copies @len bytes
 * and returns @len.
 */
static inline long
strncpy_from_user(char *to, const char __user *from, long len)
{
	if (!access_ok(from, len))
		return -EFAULT;

	might_fault();
	return __strncpy_from_user(to, from, len);
}

extern long __strnlen_user(const char __user *s, long n);

/*
 * strnlen_user: - Get the size of a string in user space.
 * @s: The string to measure.
 *
 * Context: User context only. This function may sleep if pagefaults are
 *          enabled.
 *
 * Get the size of a NUL-terminated string in user space.
 *
 * Returns the size of the string INCLUDING the terminating NUL.
 * On exception, returns 0.
 * If the string is too long, returns a value greater than @n.
 */
static inline long strnlen_user(const char __user *s, long n)
{
	if (!access_ok(s, 1))
		return 0;

	might_fault();
	return __strnlen_user(s, n);
}

#endif /* _ASM_UACCESS_H */
