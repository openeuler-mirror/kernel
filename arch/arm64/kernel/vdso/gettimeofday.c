/*
 * Userspace implementations of gettimeofday() and friends.
 *
 * Copyright (C) 2017 Cavium, Inc.
 * Copyright (C) 2012 ARM Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Will Deacon <will.deacon@arm.com>
 * Rewriten into C by: Andrew Pinski <apinski@cavium.com>
 */

#include <uapi/linux/time.h>
#include <asm/unistd.h>
#include <asm/vdso_datapage.h>
#include <linux/math64.h>
#include <linux/time.h>
#include <linux/kernel.h>

#ifdef __ILP32__
#undef BITS_PER_LONG
#define BITS_PER_LONG 32
#endif

#include <linux/hrtimer.h>

extern struct vdso_data _vdso_data;

static notrace int gettimeofday_fallback(struct timeval *_tv,
					 struct timezone *_tz)
{
	register struct timezone *tz asm("x1") = _tz;
	register struct timeval *tv asm("x0") = _tv;
	register long ret asm ("x0");
	register long nr asm("x8") = __NR_gettimeofday;

	asm volatile(
	"       svc #0\n"
	: "=r" (ret)
	: "r" (tv), "r" (tz), "r" (nr)
	: "memory");

	return ret;
}

static notrace long clock_gettime_fallback(clockid_t _clkid,
					   struct timespec *_ts)
{
	register struct timespec *ts asm("x1") = _ts;
	register clockid_t clkid asm("x0") = _clkid;
	register long ret asm ("x0");
	register long nr asm("x8") = __NR_clock_gettime;

	asm volatile(
	"       svc #0\n"
	: "=r" (ret)
	: "r" (clkid), "r" (ts), "r" (nr)
	: "memory");

	return ret;
}

static notrace int clock_getres_fallback(clockid_t _clkid,
					 struct timespec *_ts)
{
	register struct timespec *ts asm("x1") = _ts;
	register clockid_t clkid asm("x0") = _clkid;
	register long ret asm ("x0");
	register long nr asm("x8") = __NR_clock_getres;

	asm volatile(
	"       svc #0\n"
	: "=r" (ret)
	: "r" (clkid), "r" (ts), "r" (nr)
	: "memory");

	return ret;
}

static notrace u32 vdso_read_begin(struct vdso_data *vd)
{
	u32 seq;

	do {
		seq = READ_ONCE(vd->tb_seq_count);

		if ((seq & 1) == 0)
			break;

		asm volatile ("" : : : "memory");
	} while (true);

	smp_rmb(); /* Pairs with second smp_wmb in update_vsyscall */
	return seq;
}

static notrace u32 vdso_read_retry(struct vdso_data *vd, u32 start)
{
	u32 seq;

	smp_rmb(); /* Pairs with first smp_wmb in update_vsyscall */
	seq = READ_ONCE(vd->tb_seq_count);
	return seq != start;
}


/*
 * Returns the clock delta, in nanoseconds left-shifted by the clock
 * shift.
 */
static notrace u64 get_clock_shifted_nsec(u64 cycle_last, u64 mult)
{
	u64 res;

	/* Read the virtual counter. */
	isb();
	asm volatile("mrs %0, cntvct_el0" : "=r" (res) :: "memory");
	if (_vdso_data.vdso_fix) {
		u64 new;
		int retries = 50;

		asm volatile("mrs %0, cntvct_el0" : "=r" (new) :: "memory");
		while (unlikely((new - res) >> 5) && retries) {
			asm volatile("mrs %0, cntvct_el0" : "=r" (res) :: "memory");
			asm volatile("mrs %0, cntvct_el0" : "=r" (new) :: "memory");
			retries--;
		}
	}

	res = res - cycle_last;
	/* We can only guarantee 56 bits of precision. */
	res &= ~(0xff00ull<<48);

	return res * mult;
}

/*
 * Fake address dependency from the value computed from the counter
 * register to subsequent data page accesses so that the sequence
 * locking also orders the read of the counter.
 */
static notrace struct vdso_data *arch_counter_vdso_data_ordering(struct vdso_data *vd, u64 res)
{
	struct vdso_data *vd_res = vd;
	u64	tmp;

	asm	volatile(
	"	and		%0, %1, xzr\n"	\
	"	add		%2, %2, %0\n" 	\
	: "=r"	(tmp)				\
	: "r"(res), "r"(vd_res));

	return vd_res;
}

/* Code size doesn't matter (vdso is 4k/16k/64k anyway) and this is faster. */

static __always_inline notrace int do_realtime(struct vdso_data *vd,
					       struct timespec *ts)
{
	u32 seq, cs_mono_mult, cs_shift;
	u64 ns, sec, cycle_last;

	do {
		seq = vdso_read_begin(vd);

		if (vd->use_syscall)
			return -1;

		cycle_last = vd->cs_cycle_last;

		cs_mono_mult = vd->cs_mono_mult;
		cs_shift = vd->cs_shift;

		sec = vd->xtime_clock_sec;
		ns = vd->xtime_clock_nsec;

		ns += get_clock_shifted_nsec(cycle_last, cs_mono_mult);
		vd = arch_counter_vdso_data_ordering(vd, ns);
	} while (unlikely(vdso_read_retry(vd, seq)));

	ns >>= cs_shift;
	ts->tv_sec = sec + __iter_div_u64_rem(ns, NSEC_PER_SEC, &ns);
	ts->tv_nsec = ns;

	return 0;
}

static notrace int do_monotonic(struct vdso_data *vd,
				struct timespec *ts)
{
	u32 seq, cs_mono_mult, cs_shift;
	u64 ns, cycle_last, sec;

	do {
		seq = vdso_read_begin(vd);

		if (vd->use_syscall)
			return 1;

		cycle_last = vd->cs_cycle_last;

		cs_mono_mult = vd->cs_mono_mult;
		cs_shift = vd->cs_shift;

		sec = vd->xtime_clock_sec;
		ns = vd->xtime_clock_nsec;

		sec += vd->wtm_clock_sec;
		ns += vd->wtm_clock_nsec << cs_shift;

		ns += get_clock_shifted_nsec(cycle_last, cs_mono_mult);
		vd = arch_counter_vdso_data_ordering(vd, ns);
	} while (unlikely(vdso_read_retry(vd, seq)));

	ns >>= cs_shift;

	ts->tv_sec = sec + __iter_div_u64_rem(ns, NSEC_PER_SEC, &ns);
	ts->tv_nsec = ns;

	return 0;
}

static notrace int do_monotonic_raw(struct vdso_data *vd,
				    struct timespec *ts)
{
	u32 seq, cs_raw_mult, cs_shift;
	u64 ns, sec, cycle_last;

	do {
		seq = vdso_read_begin(vd);

		if (vd->use_syscall)
			return -1;

		cycle_last = vd->cs_cycle_last;

		cs_raw_mult = vd->cs_raw_mult;
		cs_shift = vd->cs_shift;

		sec = vd->raw_time_sec;
		ns = vd->raw_time_nsec;

		ns += get_clock_shifted_nsec(cycle_last, cs_raw_mult);
		vd = arch_counter_vdso_data_ordering(vd, ns);
	} while (unlikely(vdso_read_retry(vd, seq)));

	ns >>= cs_shift;
	ts->tv_sec = sec + __iter_div_u64_rem(ns, NSEC_PER_SEC, &ns);
	ts->tv_nsec = ns;

	return 0;
}


static notrace void do_realtime_coarse(struct vdso_data *vd,
				       struct timespec *ts)
{
	u32 seq;
	u64 ns, sec;

	do {
		seq = vdso_read_begin(vd);

		sec = vd->xtime_coarse_sec;
		ns = vd->xtime_coarse_nsec;

	} while (unlikely(vdso_read_retry(vd, seq)));

	ts->tv_sec = sec;
	ts->tv_nsec = ns;
}

static notrace void do_monotonic_coarse(struct vdso_data *vd,
					struct timespec *ts)
{
	u32 seq;
	u64 ns, sec, wtm_sec, wtm_ns;

	do {

		seq = vdso_read_begin(vd);

		sec = vd->xtime_coarse_sec;
		ns = vd->xtime_coarse_nsec;

		wtm_sec = vd->wtm_clock_sec;
		wtm_ns = vd->wtm_clock_nsec;

	} while (unlikely(vdso_read_retry(vd, seq)));

	sec += wtm_sec;
	ns += wtm_ns;
	ts->tv_sec = sec + __iter_div_u64_rem(ns, NSEC_PER_SEC, &ns);
	ts->tv_nsec = ns;
}

notrace int __kernel_clock_gettime(clockid_t clock, struct timespec *ts)
{
	struct vdso_data *vd = &_vdso_data;

	switch (clock) {
	case CLOCK_REALTIME:
		if (do_realtime(vd, ts))
			goto fallback;
		break;
	case CLOCK_MONOTONIC:
		if (do_monotonic(vd, ts))
			goto fallback;
		break;
	case CLOCK_MONOTONIC_RAW:
		if (do_monotonic_raw(vd, ts))
			goto fallback;
		break;
	case CLOCK_REALTIME_COARSE:
		do_realtime_coarse(vd, ts);
		break;
	case CLOCK_MONOTONIC_COARSE:
		do_monotonic_coarse(vd, ts);
		break;
	default:
		goto fallback;
	}

	return 0;
fallback:
	return clock_gettime_fallback(clock, ts);
}



notrace int __kernel_gettimeofday(struct timeval *tv, struct timezone *tz)
{
	struct vdso_data *vd = &_vdso_data;

	if (likely(tv != NULL)) {
		struct timespec ts;

		if (do_realtime(vd, &ts))
			return gettimeofday_fallback(tv, tz);

		tv->tv_sec = ts.tv_sec;
		tv->tv_usec = ts.tv_nsec / 1000;
	}

	if (unlikely(tz != NULL)) {
		tz->tz_minuteswest = vd->tz_minuteswest;
		tz->tz_dsttime = vd->tz_dsttime;
	}

	return 0;
}


int __kernel_clock_getres(clockid_t clock_id, struct timespec *res)
{
	struct vdso_data *vd = &_vdso_data;
	u64 ns;

	if (clock_id == CLOCK_REALTIME ||
	    clock_id == CLOCK_MONOTONIC ||
	    clock_id == CLOCK_MONOTONIC_RAW)
		ns = vd->hrtimer_res;
	else if (clock_id == CLOCK_REALTIME_COARSE ||
		 clock_id == CLOCK_MONOTONIC_COARSE)
		ns = LOW_RES_NSEC;
	else
		return clock_getres_fallback(clock_id, res);

	if (res) {
		res->tv_sec = 0;
		res->tv_nsec = ns;
	}

	return 0;
}
