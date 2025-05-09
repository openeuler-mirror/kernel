/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_UACCESS_64_H
#define _ASM_X86_UACCESS_64_H

/*
 * User space memory access functions
 */
#include <linux/compiler.h>
#include <linux/lockdep.h>
#include <linux/kasan-checks.h>
#include <asm/alternative.h>
#include <asm/cpufeatures.h>
#include <asm/page.h>
#if defined(CONFIG_X86_HYGON_LMC_SSE2_ON) || \
	defined(CONFIG_X86_HYGON_LMC_AVX2_ON)
#include <asm/fpu/api.h>
#endif

extern struct static_key_false hygon_lmc_key;

/*
 * Copy To/From Userspace
 */

/* Handles exceptions in both to and from, but doesn't do access_ok */
__must_check unsigned long
copy_user_enhanced_fast_string(void *to, const void *from, unsigned len);
__must_check unsigned long
copy_user_generic_string(void *to, const void *from, unsigned len);
__must_check unsigned long
copy_user_generic_unrolled(void *to, const void *from, unsigned len);

#ifdef CONFIG_X86_HYGON_LMC_SSE2_ON
void fpu_save_xmm0_3(void *to, const void *from, unsigned long len);
void fpu_restore_xmm0_3(void *to, const void *from, unsigned long len);

#define kernel_fpu_states_save fpu_save_xmm0_3
#define kernel_fpu_states_restore fpu_restore_xmm0_3

__must_check unsigned long copy_user_sse2_opt_string(void *to, const void *from,
						     unsigned long len);

#define MAX_FPU_CTX_SIZE 64
#define KERNEL_FPU_NONATOMIC_SIZE (2 * (MAX_FPU_CTX_SIZE))

#define copy_user_large_memory_generic_string copy_user_sse2_opt_string

#endif

#ifdef CONFIG_X86_HYGON_LMC_AVX2_ON
void fpu_save_ymm0_7(void *to, const void *from, unsigned long len);
void fpu_restore_ymm0_7(void *to, const void *from, unsigned long len);

#define kernel_fpu_states_save fpu_save_ymm0_7
#define kernel_fpu_states_restore fpu_restore_ymm0_7

__must_check unsigned long
copy_user_avx2_pf64_nt_string(void *to, const void *from, unsigned long len);

#define MAX_FPU_CTX_SIZE 256
#define KERNEL_FPU_NONATOMIC_SIZE (2 * (MAX_FPU_CTX_SIZE))

#define copy_user_large_memory_generic_string copy_user_avx2_pf64_nt_string
#endif

#if defined(CONFIG_X86_HYGON_LMC_SSE2_ON) || \
	defined(CONFIG_X86_HYGON_LMC_AVX2_ON)
unsigned int get_nt_block_copy_mini_len(void);
static inline bool Hygon_LMC_check(unsigned long len)
{
	unsigned int nt_blk_cpy_mini_len = get_nt_block_copy_mini_len();

	if (((nt_blk_cpy_mini_len) && (nt_blk_cpy_mini_len <= len) &&
	     (system_state == SYSTEM_RUNNING) &&
	     (!kernel_fpu_begin_nonatomic())))
		return true;
	else
		return false;
}
static inline unsigned long
copy_large_memory_generic_string(void *to, const void *from, unsigned long len)
{
	unsigned long ret;

	ret = copy_user_large_memory_generic_string(to, from, len);
	kernel_fpu_end_nonatomic();
	return ret;
}
#else
static inline bool Hygon_LMC_check(unsigned long len)
{
	return false;
}
static inline unsigned long
copy_large_memory_generic_string(void *to, const void *from, unsigned long len)
{
	return 0;
}
#endif

static __always_inline __must_check unsigned long
copy_user_generic(void *to, const void *from, unsigned len)
{
	unsigned ret;

	/* Check if Hygon large memory copy support enabled. */
	if (static_branch_unlikely(&hygon_lmc_key)) {
		if (Hygon_LMC_check(len)) {
			unsigned long ret;

			ret = copy_large_memory_generic_string(to, from, len);
			return ret;
		}
	}

	/*
	 * If CPU has ERMS feature, use copy_user_enhanced_fast_string.
	 * Otherwise, if CPU has rep_good feature, use copy_user_generic_string.
	 * Otherwise, use copy_user_generic_unrolled.
	 */
	alternative_call_2(copy_user_generic_unrolled,
			 copy_user_generic_string,
			 X86_FEATURE_REP_GOOD,
			 copy_user_enhanced_fast_string,
			 X86_FEATURE_ERMS,
			 ASM_OUTPUT2("=a" (ret), "=D" (to), "=S" (from),
				     "=d" (len)),
			 "1" (to), "2" (from), "3" (len)
			 : "memory", "rcx", "r8", "r9", "r10", "r11");
	return ret;
}

static __always_inline __must_check unsigned long
copy_to_user_mcsafe(void *to, const void *from, unsigned len)
{
	unsigned long ret;

	__uaccess_begin();
	/*
	 * Note, __memcpy_mcsafe() is explicitly used since it can
	 * handle exceptions / faults.  memcpy_mcsafe() may fall back to
	 * memcpy() which lacks this handling.
	 */
	ret = __memcpy_mcsafe(to, from, len);
	__uaccess_end();
	return ret;
}

static __always_inline __must_check unsigned long
raw_copy_from_user(void *dst, const void __user *src, unsigned long size)
{
	int ret = 0;

	if (!__builtin_constant_p(size))
		return copy_user_generic(dst, (__force void *)src, size);
	switch (size) {
	case 1:
		__uaccess_begin_nospec();
		__get_user_asm_nozero(*(u8 *)dst, (u8 __user *)src,
			      ret, "b", "b", "=q", 1);
		__uaccess_end();
		return ret;
	case 2:
		__uaccess_begin_nospec();
		__get_user_asm_nozero(*(u16 *)dst, (u16 __user *)src,
			      ret, "w", "w", "=r", 2);
		__uaccess_end();
		return ret;
	case 4:
		__uaccess_begin_nospec();
		__get_user_asm_nozero(*(u32 *)dst, (u32 __user *)src,
			      ret, "l", "k", "=r", 4);
		__uaccess_end();
		return ret;
	case 8:
		__uaccess_begin_nospec();
		__get_user_asm_nozero(*(u64 *)dst, (u64 __user *)src,
			      ret, "q", "", "=r", 8);
		__uaccess_end();
		return ret;
	case 10:
		__uaccess_begin_nospec();
		__get_user_asm_nozero(*(u64 *)dst, (u64 __user *)src,
			       ret, "q", "", "=r", 10);
		if (likely(!ret))
			__get_user_asm_nozero(*(u16 *)(8 + (char *)dst),
				       (u16 __user *)(8 + (char __user *)src),
				       ret, "w", "w", "=r", 2);
		__uaccess_end();
		return ret;
	case 16:
		__uaccess_begin_nospec();
		__get_user_asm_nozero(*(u64 *)dst, (u64 __user *)src,
			       ret, "q", "", "=r", 16);
		if (likely(!ret))
			__get_user_asm_nozero(*(u64 *)(8 + (char *)dst),
				       (u64 __user *)(8 + (char __user *)src),
				       ret, "q", "", "=r", 8);
		__uaccess_end();
		return ret;
	default:
		return copy_user_generic(dst, (__force void *)src, size);
	}
}

static __always_inline __must_check unsigned long
raw_copy_to_user(void __user *dst, const void *src, unsigned long size)
{
	int ret = 0;

	if (!__builtin_constant_p(size))
		return copy_user_generic((__force void *)dst, src, size);
	switch (size) {
	case 1:
		__uaccess_begin();
		__put_user_asm(*(u8 *)src, (u8 __user *)dst,
			      ret, "b", "b", "iq", 1);
		__uaccess_end();
		return ret;
	case 2:
		__uaccess_begin();
		__put_user_asm(*(u16 *)src, (u16 __user *)dst,
			      ret, "w", "w", "ir", 2);
		__uaccess_end();
		return ret;
	case 4:
		__uaccess_begin();
		__put_user_asm(*(u32 *)src, (u32 __user *)dst,
			      ret, "l", "k", "ir", 4);
		__uaccess_end();
		return ret;
	case 8:
		__uaccess_begin();
		__put_user_asm(*(u64 *)src, (u64 __user *)dst,
			      ret, "q", "", "er", 8);
		__uaccess_end();
		return ret;
	case 10:
		__uaccess_begin();
		__put_user_asm(*(u64 *)src, (u64 __user *)dst,
			       ret, "q", "", "er", 10);
		if (likely(!ret)) {
			asm("":::"memory");
			__put_user_asm(4[(u16 *)src], 4 + (u16 __user *)dst,
				       ret, "w", "w", "ir", 2);
		}
		__uaccess_end();
		return ret;
	case 16:
		__uaccess_begin();
		__put_user_asm(*(u64 *)src, (u64 __user *)dst,
			       ret, "q", "", "er", 16);
		if (likely(!ret)) {
			asm("":::"memory");
			__put_user_asm(1[(u64 *)src], 1 + (u64 __user *)dst,
				       ret, "q", "", "er", 8);
		}
		__uaccess_end();
		return ret;
	default:
		return copy_user_generic((__force void *)dst, src, size);
	}
}

static __always_inline __must_check
unsigned long raw_copy_in_user(void __user *dst, const void __user *src, unsigned long size)
{
	return copy_user_generic((__force void *)dst,
				 (__force void *)src, size);
}

extern long __copy_user_nocache(void *dst, const void __user *src,
				unsigned size, int zerorest);

extern long __copy_user_flushcache(void *dst, const void __user *src, unsigned size);
extern void memcpy_page_flushcache(char *to, struct page *page, size_t offset,
			   size_t len);

static inline int
__copy_from_user_inatomic_nocache(void *dst, const void __user *src,
				  unsigned size)
{
	kasan_check_write(dst, size);
	return __copy_user_nocache(dst, src, size, 0);
}

static inline int
__copy_from_user_flushcache(void *dst, const void __user *src, unsigned size)
{
	kasan_check_write(dst, size);
	return __copy_user_flushcache(dst, src, size);
}

unsigned long
mcsafe_handle_tail(char *to, char *from, unsigned len);

#endif /* _ASM_X86_UACCESS_64_H */
