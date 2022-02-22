/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_BITOPS_H
#define _ASM_SW64_BITOPS_H

#ifndef _LINUX_BITOPS_H
#error only <linux/bitops.h> can be included directly
#endif

#include <asm/compiler.h>
#include <asm/barrier.h>

/*
 * Copyright 1994, Linus Torvalds.
 */

/*
 * These have to be done with inline assembly: that way the bit-setting
 * is guaranteed to be atomic. All bit operations return 0 if the bit
 * was cleared before the operation and != 0 if it was not.
 *
 * To get proper branch prediction for the main line, we must branch
 * forward to code at the end of this object's .text section, then
 * branch back to restart the operation.
 *
 * bit 0 is the LSB of addr; bit 64 is the LSB of (addr+1).
 */

static inline void
set_bit(unsigned long nr, volatile void *addr)
{
	unsigned long temp1, temp2, base;
	int *m = ((int *) addr) + (nr >> 5);

	__asm__ __volatile__(
#ifdef CONFIG_LOCK_MEMB
	"	memb\n"
#endif
	"	ldi	%3, %5\n"
	"1:	lldw	%0, 0(%3)\n"
	"	ldi	%1, 1\n"
	"	wr_f	%1\n"
	"	bis	%0, %4, %0\n"
#ifdef CONFIG_LOCK_FIXUP
	"	memb\n"
#endif
	"	lstw	%0, 0(%3)\n"
	"	rd_f	%1\n"
	"	beq	%1, 2f\n"
	".subsection 2\n"
	"2:	br	1b\n"
	".previous"
	: "=&r" (temp1), "=&r" (temp2), "=m" (*m), "=&r" (base)
	: "Ir" (1UL << (nr & 31)), "m" (*m));
}

/*
 * WARNING: non atomic version.
 */
static inline void
__set_bit(unsigned long nr, volatile void *addr)
{
	int *m = ((int *) addr) + (nr >> 5);

	*m |= 1 << (nr & 31);
}

#define smp_mb__before_clear_bit()	smp_mb()
#define smp_mb__after_clear_bit()	smp_mb()

static inline void
clear_bit(unsigned long nr, volatile void *addr)
{
	unsigned long temp1, temp2, base;
	int *m = ((int *) addr) + (nr >> 5);

	__asm__ __volatile__(
#ifdef CONFIG_LOCK_MEMB
	"	memb\n"
#endif
	"	ldi	%3, %5\n"
	"1:	lldw	%0, 0(%3)\n"
	"	ldi	%1, 1\n"
	"	wr_f	%1\n"
	"	bic	%0, %4, %0\n"
#ifdef CONFIG_LOCK_FIXUP
	"	memb\n"
#endif
	"	lstw	%0, 0(%3)\n"
	"	rd_f	%1\n"
	"	beq	%1, 2f\n"
	".subsection 2\n"
	"2:	br	1b\n"
	".previous"
	: "=&r" (temp1), "=&r" (temp2), "=m" (*m), "=&r" (base)
	: "Ir" (1UL << (nr & 31)), "m" (*m));
}

static inline void
clear_bit_unlock(unsigned long nr, volatile void *addr)
{
	smp_mb();
	clear_bit(nr, addr);
}

/*
 * WARNING: non atomic version.
 */
static inline void
__clear_bit(unsigned long nr, volatile void *addr)
{
	int *m = ((int *) addr) + (nr >> 5);

	*m &= ~(1 << (nr & 31));
}

static inline void
__clear_bit_unlock(unsigned long nr, volatile void *addr)
{
	smp_mb();
	__clear_bit(nr, addr);
}

static inline void
change_bit(unsigned long nr, volatile void *addr)
{
	unsigned long temp1, temp2, base;
	int *m = ((int *) addr) + (nr >> 5);

	__asm__ __volatile__(
#ifdef CONFIG_LOCK_MEMB
	"	memb\n"
#endif
	"	ldi	%3, %5\n"
	"1:	lldw	%0, 0(%3)\n"
	"	ldi	%1, 1\n"
	"	wr_f	%1\n"
	"	xor	%0, %4, %0\n"
#ifdef CONFIG_LOCK_FIXUP
	"	memb\n"
#endif
	"	lstw	%0, 0(%3)\n"
	"	rd_f	%1\n"
	"	beq	%1, 2f\n"
	".subsection 2\n"
	"2:	br	1b\n"
	".previous"
	: "=&r" (temp1), "=&r" (temp2), "=m" (*m), "=&r" (base)
	: "Ir" (1UL << (nr & 31)), "m" (*m));
}

/*
 * WARNING: non atomic version.
 */
static inline void
__change_bit(unsigned long nr, volatile void *addr)
{
	int *m = ((int *) addr) + (nr >> 5);

	*m ^= 1 << (nr & 31);
}


static inline int
test_and_set_bit(unsigned long nr, volatile void *addr)
{
	unsigned long oldbit;
	unsigned long temp1, temp2, base;
	int *m = ((int *) addr) + (nr >> 5);

	__asm__ __volatile__(
#ifdef CONFIG_LOCK_MEMB
	"	memb\n"
#endif
	"	ldi	%4, %6\n"
	"1:	lldw	%0, 0(%4)\n"
	"	and	%0, %5, %3\n"
	"	seleq	%3, 1, $31, %1\n"
	"	wr_f	%1\n"
	"	bis	%0, %5, %0\n"
#ifdef CONFIG_LOCK_FIXUP
	"	memb\n"
#endif
	"	lstw	%0, 0(%4)\n"
	"	rd_f	%0\n"
	"	bne	%3, 2f\n"		// %3 is not zero, no need to set, return
	"	beq	%0, 3f\n"		// failed to set, try again.
	"2:\n"
	".subsection 2\n"
	"3:	br 1b\n"
	".previous"
	: "=&r" (temp1), "=&r" (temp2), "=m" (*m), "=&r" (oldbit), "=&r" (base)
	: "Ir" (1UL << (nr & 31)), "m" (*m) : "memory");

	return oldbit != 0;
}

static inline int
test_and_set_bit_lock(unsigned long nr, volatile void *addr)
{
	unsigned long oldbit;
	unsigned long temp1, temp2, base;
	int *m = ((int *) addr) + (nr >> 5);

	__asm__ __volatile__(
#ifdef CONFIG_LOCK_MEMB
	"	memb\n"
#endif
	"	ldi	%4, %6\n"
	"1:	lldw	%0, 0(%4)\n"
	"	and	%0, %5, %3\n"
	"	seleq	%3, 1, $31, %1\n"
	"	wr_f	%1\n"
	"	bis	%0, %5, %0\n"
#ifdef CONFIG_LOCK_FIXUP
	"	memb\n"
#endif
	"	lstw	%0, 0(%4)\n"
	"	rd_f	%0\n"
	"	bne	%3, 2f\n"		// %3 is not zero, no need to set, return
	"	beq	%0, 3f\n"		// failed to set, try again.
	"2:\n"
	".subsection 2\n"
	"3:	br 1b\n"
	".previous"
	: "=&r" (temp1), "=&r" (temp2), "=m" (*m), "=&r" (oldbit), "=&r" (base)
	: "Ir" (1UL << (nr & 31)), "m" (*m) : "memory");

	return oldbit != 0;
}

/*
 * WARNING: non atomic version.
 */
static inline int
__test_and_set_bit(unsigned long nr, volatile void *addr)
{
	unsigned long mask = 1 << (nr & 0x1f);
	int *m = ((int *) addr) + (nr >> 5);
	int old = *m;

	*m = old | mask;
	return (old & mask) != 0;
}

static inline int
test_and_clear_bit(unsigned long nr, volatile void *addr)
{
	unsigned long oldbit;
	unsigned long temp1, temp2, base;
	int *m = ((int *) addr) + (nr >> 5);

	__asm__ __volatile__(
#ifdef CONFIG_LOCK_MEMB
	"	memb\n"
#endif
	"	ldi	%4, %6\n"
	"1:	lldw	%0, 0(%4)\n"
	"	and	%0, %5, %3\n"
	"	selne	%3, 1, $31, %1\n"	//Note: here is SELNE!!!
	"	wr_f	%1\n"
	"	bic	%0, %5, %0\n"
#ifdef CONFIG_LOCK_FIXUP
	"	memb\n"
#endif
	"	lstw	%0, 0(%4)\n"
	"	rd_f	%0\n"
	"	beq	%3, 2f\n"		// %3 is zero, no need to set, return
	"	beq	%0, 3f\n"		// failed to set, try again.
	"2:\n"
	".subsection 2\n"
	"3:	br 1b\n"
	".previous"
	: "=&r" (temp1), "=&r" (temp2), "=m" (*m), "=&r" (oldbit), "=&r" (base)
	: "Ir" (1UL << (nr & 31)), "m" (*m) : "memory");

	return oldbit != 0;
}

/*
 * WARNING: non atomic version.
 */
static inline int
__test_and_clear_bit(unsigned long nr, volatile void *addr)
{
	unsigned long mask = 1 << (nr & 0x1f);
	int *m = ((int *) addr) + (nr >> 5);
	int old = *m;

	*m = old & ~mask;
	return (old & mask) != 0;
}

static inline int
test_and_change_bit(unsigned long nr, volatile void *addr)
{
	unsigned long oldbit;
	unsigned long temp, base;
	int *m = ((int *) addr) + (nr >> 5);

	__asm__ __volatile__(
#ifdef CONFIG_LOCK_MEMB
	"	memb\n"
#endif
	"	ldi	%3, %5\n"
	"1:	lldw	%0, 0(%3)\n"
	"	ldi	%2, 1\n"
	"	wr_f	%2\n"
	"	and	%0, %4, %2\n"
	"	xor	%0, %4, %0\n"
#ifdef CONFIG_LOCK_FIXUP
	"	memb\n"
#endif
	"	lstw	%0, 0(%3)\n"
	"	rd_f	%0\n"
	"	beq	%0, 3f\n"
	".subsection 2\n"
	"3:	br 1b\n"
	".previous"
	: "=&r" (temp), "=m" (*m), "=&r" (oldbit), "=&r" (base)
	: "Ir" (1UL << (nr & 31)), "m" (*m) : "memory");

	return oldbit != 0;
}

/*
 * WARNING: non atomic version.
 */
static inline int
__test_and_change_bit(unsigned long nr, volatile void *addr)
{
	unsigned long mask = 1 << (nr & 0x1f);
	int *m = ((int *) addr) + (nr >> 5);
	int old = *m;

	*m = old ^ mask;
	return (old & mask) != 0;
}

static inline int
test_bit(int nr, const volatile void *addr)
{
	return (1UL & (((const int *) addr)[nr >> 5] >> (nr & 31))) != 0UL;
}

/*
 * ffz = Find First Zero in word. Undefined if no zero exists,
 * so code should check against ~0UL first..
 *
 * Do a binary search on the bits.  Due to the nature of large
 * constants on the sw64, it is worthwhile to split the search.
 */
static inline unsigned long ffz_b(unsigned long x)
{
	unsigned long sum, x1, x2, x4;

	x = ~x & -~x;		/* set first 0 bit, clear others */
	x1 = x & 0xAA;
	x2 = x & 0xCC;
	x4 = x & 0xF0;
	sum = x2 ? 2 : 0;
	sum += (x4 != 0) * 4;
	sum += (x1 != 0);

	return sum;
}

static inline unsigned long ffz(unsigned long word)
{
	return __kernel_cttz(~word);
}

/*
 * __ffs = Find First set bit in word.  Undefined if no set bit exists.
 */
static inline unsigned long __ffs(unsigned long word)
{
	return __kernel_cttz(word);
}

#ifdef __KERNEL__

/*
 * ffs: find first bit set. This is defined the same way as
 * the libc and compiler builtin ffs routines, therefore
 * differs in spirit from the above __ffs.
 */

static inline int ffs(int word)
{
	int result = __ffs(word) + 1;

	return word ? result : 0;
}

/*
 * fls: find last bit set.
 */
static inline int fls64(unsigned long word)
{
	return 64 - __kernel_ctlz(word);
}

static inline unsigned long __fls(unsigned long x)
{
	return fls64(x) - 1;
}

static inline int fls(int x)
{
	return fls64((unsigned int) x);
}

/*
 * hweightN: returns the hamming weight (i.e. the number
 * of bits set) of a N-bit word
 */

static inline unsigned long __arch_hweight64(unsigned long w)
{
	return __kernel_ctpop(w);
}

static inline unsigned int __arch_hweight32(unsigned int w)
{
	return __arch_hweight64(w);
}

static inline unsigned int __arch_hweight16(unsigned int w)
{
	return __arch_hweight64(w & 0xffff);
}

static inline unsigned int __arch_hweight8(unsigned int w)
{
	return __arch_hweight64(w & 0xff);
}

#include <asm-generic/bitops/const_hweight.h>

#endif /* __KERNEL__ */

#include <asm-generic/bitops/find.h>

#ifdef __KERNEL__

/*
 * Every architecture must define this function. It's the fastest
 * way of searching a 100-bit bitmap.  It's guaranteed that at least
 * one of the 100 bits is cleared.
 */
static inline unsigned long
sched_find_first_bit(const unsigned long b[2])
{
	unsigned long b0, b1, ofs, tmp;

	b0 = b[0];
	b1 = b[1];
	ofs = (b0 ? 0 : 64);
	tmp = (b0 ? b0 : b1);

	return __ffs(tmp) + ofs;
}

#include <asm-generic/bitops/le.h>

#include <asm-generic/bitops/ext2-atomic-setbit.h>

#endif /* __KERNEL__ */

#endif /* _ASM_SW64_BITOPS_H */
