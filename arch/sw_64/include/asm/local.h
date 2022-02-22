/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_LOCAL_H
#define _ASM_SW64_LOCAL_H

#include <linux/percpu.h>
#include <linux/atomic.h>

typedef struct {
	atomic_long_t a;
} local_t;

#define LOCAL_INIT(i)	{ ATOMIC_LONG_INIT(i) }
#define local_read(l)	atomic_long_read(&(l)->a)
#define local_set(l, i)	atomic_long_set(&(l)->a, (i))
#define local_inc(l)	atomic_long_inc(&(l)->a)
#define local_dec(l)	atomic_long_dec(&(l)->a)
#define local_add(i, l)	atomic_long_add((i), (&(l)->a))
#define local_sub(i, l)	atomic_long_sub((i), (&(l)->a))

static inline long local_add_return(long i, local_t *l)
{
	long temp1, temp2, result, addr;

	__asm__ __volatile__(
#ifdef CONFIG_LOCK_MEMB
	"	memb\n"
#endif
	"	ldi  %4, %2\n"
	"1:	lldl %0, 0(%4)\n"
	"	ldi  %1, 1\n"
	"	wr_f %1\n"
	"	addl %0, %5, %3\n"
	"	addl %0, %5, %0\n"
#ifdef CONFIG_LOCK_FIXUP
	"	memb\n"
#endif
	"	lstl %0, 0(%4)\n"
	"	rd_f %0\n"
	"	beq %0, 2f\n"
	".subsection 2\n"
	"2:	br 1b\n"
	".previous"
	: "=&r" (temp1), "=&r" (temp2), "=m" (l->a.counter),
	  "=&r" (result), "=&r" (addr)
	: "Ir" (i), "m" (l->a.counter) : "memory");
	return result;
}

static inline long local_sub_return(long i, local_t *l)
{
	long temp1, temp2, result, addr;

	__asm__ __volatile__(
#ifdef CONFIG_LOCK_MEMB
	"	memb\n"
#endif
	"	ldi  %4, %2\n"
	"1:	lldl %0, 0(%4)\n"
	"	ldi  %1, 1\n"
	"	wr_f %1\n"
	"	subl %0, %5, %3\n"
	"	subl %0, %5, %0\n"
#ifdef CONFIG_LOCK_FIXUP
	"       memb\n"
#endif
	"	lstl %0, 0(%4)\n"
	"	rd_f %0\n"
	"	beq %0, 2f\n"
	".subsection 2\n"
	"2:	br 1b\n"
	".previous"
	: "=&r" (temp1), "=&r" (temp2), "=m" (l->a.counter),
	  "=&r" (result), "=&r" (addr)
	: "Ir" (i), "m" (l->a.counter) : "memory");
	return result;
}

#define local_cmpxchg(l, o, n) \
	(cmpxchg_local(&((l)->a.counter), (o), (n)))
#define local_xchg(l, n) (xchg_local(&((l)->a.counter), (n)))

/**
 * local_add_unless - add unless the number is a given value
 * @l: pointer of type local_t
 * @a: the amount to add to l...
 * @u: ...unless l is equal to u.
 *
 * Atomically adds @a to @l, so long as it was not @u.
 * Returns non-zero if @l was not @u, and zero otherwise.
 */
#define local_add_unless(l, a, u)				\
({								\
	long c, old;						\
	c = local_read(l);					\
	for (;;) {						\
		if (unlikely(c == (u)))				\
			break;					\
		old = local_cmpxchg((l), c, c + (a));	\
		if (likely(old == c))				\
			break;					\
		c = old;					\
	}							\
	c != (u);						\
})
#define local_inc_not_zero(l) local_add_unless((l), 1, 0)

#define local_add_negative(a, l) (local_add_return((a), (l)) < 0)

#define local_dec_return(l) local_sub_return(1, (l))

#define local_inc_return(l) local_add_return(1, (l))

#define local_sub_and_test(i, l) (local_sub_return((i), (l)) == 0)

#define local_inc_and_test(l) (local_add_return(1, (l)) == 0)

#define local_dec_and_test(l) (local_sub_return(1, (l)) == 0)

/* Verify if faster than atomic ops */
#define __local_inc(l)		((l)->a.counter++)
#define __local_dec(l)		((l)->a.counter++)
#define __local_add(i, l)	((l)->a.counter += (i))
#define __local_sub(i, l)	((l)->a.counter -= (i))

#endif /* _ASM_SW64_LOCAL_H */
