/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_ATOMIC_H
#define _ASM_SW64_ATOMIC_H

#include <linux/types.h>
#include <asm/barrier.h>
#include <asm/cmpxchg.h>

/*
 * Atomic operations that C can't guarantee us.  Useful for
 * resource counting etc...
 *
 * But use these as seldom as possible since they are much slower
 * than regular operations.
 */

#define ATOMIC_INIT(i)		{ (i) }
#define ATOMIC64_INIT(i)	{ (i) }

#define atomic_read(v)		READ_ONCE((v)->counter)
#define atomic64_read(v)	READ_ONCE((v)->counter)

#define atomic_set(v, i)	WRITE_ONCE((v)->counter, (i))
#define atomic64_set(v, i)	WRITE_ONCE((v)->counter, (i))

/*
 * To get proper branch prediction for the main line, we must branch
 * forward to code at the end of this object's .text section, then
 * branch back to restart the operation.
 */
#define atomic64_cmpxchg(v, old, new) (cmpxchg(&((v)->counter), old, new))
#define atomic64_xchg(v, new) (xchg(&((v)->counter), new))

#define atomic_cmpxchg(v, old, new) (cmpxchg(&((v)->counter), old, new))
#define atomic_xchg(v, new) (xchg(&((v)->counter), new))


/**
 * atomic_fetch_add_unless - add unless the number is a given value
 * @v: pointer of type atomic_t
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @v, so long as it was not @u.
 * Returns the old value of @v.
 */
static inline int atomic_fetch_add_unless(atomic_t *v, int a, int u)
{
	int old, new, c;
	unsigned long addr;

	__asm__ __volatile__(
#ifdef CONFIG_LOCK_MEMB
	"	memb\n"
#endif
	"	ldi	%3, %2\n"
	"1:	lldw	%0, 0(%3)\n"
	"	cmpeq	%0, %5, %4\n"
	"	seleq	%4, 1, $31, %4\n"
	"	wr_f	%4\n"
	"	addw	%0, %6, %1\n"
#ifdef CONFIG_LOCK_FIXUP
	"	memb\n"
#endif
	"	lstw	%1, 0(%3)\n"
	"	rd_f	%1\n"
	"	beq	%4, 2f\n"
	"	beq	%1, 3f\n"
	"2:\n"
	".subsection 2\n"
	"3:	br 1b\n"
	".previous"
	: "=&r" (old), "=&r" (new), "=m" (v->counter), "=&r" (addr), "=&r" (c)
	: "Ir" (u), "Ir" (a), "m" (v->counter));
	return old;
}
#define atomic_fetch_add_unless atomic_fetch_add_unless
/**
 * atomic64_fetch_add_unless - add unless the number is a given value
 * @v: pointer of type atomic64_t
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @v, so long as it was not @u.
 * Returns the old value of @v.
 */
static inline long atomic64_fetch_add_unless(atomic64_t *v, long a, long u)
{
	long old, new, c;
	unsigned long addr;

	__asm__ __volatile__(
#ifdef CONFIG_LOCK_MEMB
	"	memb\n"
#endif
	"	ldi	%3, %2\n"
	"1:	lldl	%0, 0(%3)\n"
	"	cmpeq	%0, %5, %4\n"
	"	seleq	%4, 1, $31, %4\n"
	"	wr_f	%4\n"
	"	addl	%0, %6, %1\n"
#ifdef CONFIG_LOCK_FIXUP
	"	memb\n"
#endif
	"	lstl	%1, 0(%3)\n"
	"	rd_f	%1\n"
	"	beq	%4, 2f\n"
	"	beq	%1, 3f\n"
	"2:\n"
	".subsection 2\n"
	"3:	br 1b\n"
	".previous"
	: "=&r" (old), "=&r" (new), "=m" (v->counter), "=&r" (addr), "=&r" (c)
	: "Ir" (u), "Ir" (a), "m" (v->counter));
	return old;
}
#define atomic64_fetch_add_unless atomic64_fetch_add_unless
/*
 * atomic64_dec_if_positive - decrement by 1 if old value positive
 * @v: pointer of type atomic_t
 *
 * The function returns the old value of *v minus 1, even if
 * the atomic variable, v, was not decremented.
 */
static inline long atomic64_dec_if_positive(atomic64_t *v)
{
	unsigned long old, temp1, addr, temp2;

	__asm__ __volatile__(
#ifdef CONFIG_LOCK_MEMB
	"	memb\n"
#endif
	"	ldi	%3, %2\n"
	"1:	lldl	%4, 0(%3)\n"
	"	cmple	%4, 0, %0\n"
	"	seleq	%0, 1, $31, %0\n"
	"	wr_f	%0\n"
	"	subl	%4, 1, %1\n"
#ifdef CONFIG_LOCK_FIXUP
	"	memb\n"
#endif
	"	lstl	%1, 0(%3)\n"
	"	rd_f	%1\n"
	"	beq	%0, 2f\n"
	"	beq	%1, 3f\n"
	"2:\n"
	".subsection 2\n"
	"3:	br 1b\n"
	".previous"
	: "=&r" (temp1), "=&r" (temp2), "=m" (v->counter), "=&r" (addr), "=&r" (old)
	: "m" (v->counter));
	return old - 1;
}


#define atomic64_dec_if_positive atomic64_dec_if_positive

#ifdef CONFIG_LOCK_MEMB
#define LOCK_MEMB	"memb\n"
#else
#define LOCK_MEMB
#endif

#ifdef CONFIG_LOCK_FIXUP
#define LOCK_FIXUP	"memb\n"
#else
#define LOCK_FIXUP
#endif


#define ATOMIC_OP(op, asm_op)						\
static inline void atomic_##op(int i, atomic_t *v)			\
{									\
	unsigned long temp1, temp2, addr;				\
	__asm__ __volatile__(						\
	LOCK_MEMB							\
	"	ldi	%3, %2\n"					\
	"1:	lldw	%0, 0(%3)\n"					\
	"	ldi	%1, 1\n"					\
	"	wr_f	%1\n"						\
	"	" #asm_op " %0, %4, %0\n"				\
	LOCK_FIXUP							\
	"	lstw	%0, 0(%3)\n"					\
	"	rd_f	%0\n"						\
	"	beq	%0, 2f\n"					\
	".subsection 2\n"						\
	"2:	br 1b\n"						\
	".previous"							\
	: "=&r" (temp1), "=&r" (temp2), "=m" (v->counter), "=&r" (addr) \
	: "Ir" (i), "m" (v->counter));					\
}									\


#define ATOMIC_OP_RETURN(op, asm_op)					\
static inline int atomic_##op##_return_relaxed(int i, atomic_t *v)	\
{									\
	int temp1, temp2;						\
	unsigned long addr;						\
	__asm__ __volatile__(						\
	LOCK_MEMB							\
	"	ldi	%3, %2\n"					\
	"1:	lldw	%0, 0(%3)\n"					\
	"	ldi	%1, 1\n"					\
	"	wr_f	%1\n"						\
	"	" #asm_op " %0, %4, %1\n"				\
	"	" #asm_op " %0, %4, %0\n"				\
	LOCK_FIXUP							\
	"	lstw	%1, 0(%3)\n"					\
	"	rd_f	%1\n"						\
	"	beq	%1, 2f\n"					\
	".subsection 2\n"						\
	"2:	br 1b\n"						\
	".previous"							\
	: "=&r" (temp1), "=&r" (temp2), "=m" (v->counter), "=&r" (addr)	\
	: "Ir" (i), "m" (v->counter));					\
	return temp1;							\
}                                                                       \



#define ATOMIC_FETCH_OP(op, asm_op)                                     \
static inline int atomic_fetch_##op##_relaxed(int i, atomic_t *v)	\
{									\
	int temp1, temp2;						\
	unsigned long addr;						\
	__asm__ __volatile__(						\
	LOCK_MEMB							\
	"	ldi	%3, %2\n"					\
	"1:	lldw	%0, 0(%3)\n"					\
	"	ldi	%1, 1\n"					\
	"	wr_f	%1\n"						\
	"	" #asm_op " %0, %4, %1\n"				\
	LOCK_FIXUP							\
	"	lstw	%1, 0(%3)\n"					\
	"	rd_f	%1\n"						\
	"	beq	%1, 2f\n"					\
	".subsection 2\n"						\
	"2:	br 1b\n"						\
	".previous"							\
	: "=&r" (temp1), "=&r" (temp2), "=m" (v->counter), "=&r" (addr)	\
	: "Ir" (i), "m" (v->counter));					\
	return temp1;							\
}                                                                       \


#define ATOMIC64_OP(op, asm_op)                                         \
static inline void atomic64_##op(long i, atomic64_t *v)			\
{									\
	unsigned long temp1, temp2, addr;				\
	__asm__ __volatile__(						\
	LOCK_MEMB							\
	"	ldi	%3, %2\n"					\
	"1:	lldl	%0, 0(%3)\n"					\
	"	ldi	%1, 1\n"					\
	"	wr_f	%1\n"						\
	"	" #asm_op " %0, %4, %0\n"				\
	LOCK_FIXUP							\
	"	lstl	%0, 0(%3)\n"					\
	"	rd_f	%0\n"						\
	"	beq	%0, 2f\n"					\
	".subsection 2\n"						\
	"2:	br 1b\n"						\
	".previous"							\
	: "=&r" (temp1), "=&r" (temp2), "=m" (v->counter), "=&r" (addr)	\
	: "Ir" (i), "m" (v->counter));					\
}									\


#define ATOMIC64_OP_RETURN(op, asm_op)                                  \
static inline long atomic64_##op##_return_relaxed(long i, atomic64_t *v)\
{									\
	long temp1, temp2;						\
	unsigned long addr;						\
	__asm__ __volatile__(						\
	LOCK_MEMB							\
	"	ldi	%3, %2\n"					\
	"1:	lldl	%0, 0(%3)\n"					\
	"	ldi	%1, 1\n"					\
	"	wr_f	%1\n"						\
	"	" #asm_op " %0, %4, %1\n"				\
	"	" #asm_op " %0, %4, %0\n"				\
	LOCK_FIXUP							\
	"	lstl	%1, 0(%3)\n"					\
	"	rd_f	%1\n"						\
	"	beq	%1, 2f\n"					\
	".subsection 2\n"						\
	"2:	br 1b\n"						\
	".previous"							\
	: "=&r" (temp1), "=&r" (temp2), "=m" (v->counter), "=&r" (addr)	\
	: "Ir" (i), "m" (v->counter));					\
	return temp1;							\
}

#define ATOMIC64_FETCH_OP(op, asm_op)					\
static inline long atomic64_fetch_##op##_relaxed(long i, atomic64_t *v) \
{									\
	long temp1, temp2;						\
	unsigned long addr;						\
	__asm__ __volatile__(						\
	LOCK_MEMB							\
	"	ldi	%3, %2\n"					\
	"1:	lldl	%0, 0(%3)\n"					\
	"	ldi	%1, 1\n"					\
	"	wr_f	%1\n"						\
	"	" #asm_op " %0, %4, %1\n"				\
	LOCK_FIXUP							\
	"	lstl	%1, 0(%3)\n"					\
	"	rd_f	%1\n"						\
	"	beq	%1, 2f\n"					\
	".subsection 2\n"						\
	"2:	br 1b\n"						\
	".previous"							\
	: "=&r" (temp1), "=&r" (temp2), "=m" (v->counter), "=&r" (addr)	\
	: "Ir" (i), "m" (v->counter));					\
	return temp1;							\
}                                                                       \

#define ATOMIC_OPS(op)                                                  \
	ATOMIC_OP(op, op##w)                                            \
	ATOMIC_OP_RETURN(op, op##w)					\
	ATOMIC_FETCH_OP(op, op##w)					\
	ATOMIC64_OP(op, op##l)                                          \
	ATOMIC64_OP_RETURN(op, op##l)					\
	ATOMIC64_FETCH_OP(op, op##l)					\

ATOMIC_OPS(add)
ATOMIC_OPS(sub)

#define atomic_add_return_relaxed	atomic_add_return_relaxed
#define atomic_sub_return_relaxed	atomic_sub_return_relaxed
#define atomic_fetch_add_relaxed	atomic_fetch_add_relaxed
#define atomic_fetch_sub_relaxed	atomic_fetch_sub_relaxed

#define atomic64_add_return_relaxed	atomic64_add_return_relaxed
#define atomic64_sub_return_relaxed	atomic64_sub_return_relaxed
#define atomic64_fetch_add_relaxed	atomic64_fetch_add_relaxed
#define atomic64_fetch_sub_relaxed	atomic64_fetch_sub_relaxed

#undef ATOMIC_OPS

#define ATOMIC_OPS(op, asm)						\
	ATOMIC_OP(op, asm)                                              \
	ATOMIC_FETCH_OP(op, asm)					\
	ATOMIC64_OP(op, asm)                                            \
	ATOMIC64_FETCH_OP(op, asm)					\

ATOMIC_OPS(and, and)
ATOMIC_OPS(andnot, bic)
ATOMIC_OPS(or, bis)
ATOMIC_OPS(xor, xor)

#define atomic_fetch_and_relaxed	atomic_fetch_and_relaxed
#define atomic_fetch_andnot_relaxed	atomic_fetch_andnot_relaxed
#define atomic_fetch_or_relaxed		atomic_fetch_or_relaxed
#define atomic_fetch_xor_relaxed	atomic_fetch_xor_relaxed

#define atomic64_fetch_and_relaxed	atomic64_fetch_and_relaxed
#define atomic64_fetch_andnot_relaxed	atomic64_fetch_andnot_relaxed
#define atomic64_fetch_or_relaxed	atomic64_fetch_or_relaxed
#define atomic64_fetch_xor_relaxed	atomic64_fetch_xor_relaxed

#undef ATOMIC_OPS
#undef ATOMIC64_FETCH_OP
#undef ATOMIC64_OP_RETURN
#undef ATOMIC64_OP
#undef ATOMIC_FETCH_OP
#undef ATOMIC_OP_RETURN
#undef ATOMIC_OP

#define atomic_andnot atomic_andnot
#define atomic64_andnot atomic64_andnot

#endif /* _ASM_SW64_ATOMIC_H */
