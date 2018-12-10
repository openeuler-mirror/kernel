#ifndef _ROCE_K_COMPAT_H
#define _ROCE_K_COMPAT_H

#ifndef LINUX_VERSION_CODE
#include <linux/version.h>
#else
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))
#endif

#ifndef PCI_VENDOR_ID_HUAWEI
#define PCI_VENDOR_ID_HUAWEI		0x19e5
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0))

/**
 * OFED didn't provide a version code
 * !!!!! This is a TEMPORARILY solution !!!!!
 */

#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0))
typedef unsigned long long __u64;

#if defined(__GNUC__)
typedef		__u64		uint64_t;
#endif

typedef uint64_t u64;
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0))
#undef pci_irq_vector
#define pci_irq_vector _kc_pci_irq_vector
#ifdef CONFIG_PCI_MSI
#include <linux/pci.h>
#include <linux/msi.h>
/**
 * pci_irq_vector - return Linux IRQ number of a device vector
 * @dev: PCI device to operate on
 * @nr: device-relative interrupt vector index (0-based).
 */
static inline int _kc_pci_irq_vector(struct pci_dev *dev, unsigned int nr)
{
	if (dev->msix_enabled) {
		struct msi_desc *entry;
		int i = 0;

		for_each_pci_msi_entry(entry, dev) {
			if (i == nr)
				return entry->irq;
			i++;
		}
		WARN_ON_ONCE(1);
		return -EINVAL;
	}

	if (dev->msi_enabled) {
		struct msi_desc *entry = first_pci_msi_entry(dev);

		if (WARN_ON_ONCE(nr >= entry->nvec_used))
			return -EINVAL;
	} else {
		if (WARN_ON_ONCE(nr > 0))
			return -EINVAL;
	}

	return dev->irq + nr;
}
#else
static inline int _kc_pci_irq_vector(struct pci_dev *dev, unsigned int nr)
{
	if (WARN_ON_ONCE(nr > 0))
		return -EINVAL;
	return dev->irq;
}
#endif
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0))

#ifndef HAVE_LINUX_MM_H
#define HAVE_LINUX_MM_H
#endif

#ifndef HAVE_LINUX_SCHED_H
#define HAVE_LINUX_SCHED_H
#endif
/**
 * struct refcount_t - variant of atomic_t specialized for reference counts
 * @refs: atomic_t counter field
 *
 * The counter saturates at UINT_MAX and will not move once
 * there. This avoids wrapping the counter and causing 'spurious'
 * use-after-free bugs.
 */
typedef struct refcount_struct {
	atomic_t refs;
} refcount_t;

/**
 * refcount_set - set a refcount's value
 * @r: the refcount
 * @n: value to which the refcount will be set
 */
#undef refcount_set
#define refcount_set _kc_refcount_set
static inline void _kc_refcount_set(refcount_t *r, unsigned int n)
{
	atomic_set(&r->refs, n);
}

#undef refcount_dec_and_test
#define refcount_dec_and_test _kc_refcount_dec_and_test
static inline __must_check bool _kc_refcount_dec_and_test(refcount_t *r)
{
	return atomic_dec_and_test(&r->refs);
}

/*
 * Similar to atomic_inc_not_zero(), will saturate at UINT_MAX and WARN.
 *
 * Provides no memory ordering, it is assumed the caller has guaranteed the
 * object memory to be stable (RCU, etc.). It does provide a control dependency
 * and thereby orders future stores. See the comment on top.
 */
static inline bool refcount_inc_not_zero(refcount_t *r)
{
	unsigned int old, new, val = atomic_read(&r->refs);

	for (;;) {
		new = val + 1;

		if (!val)
			return false;

		if (unlikely(!new))
			return true;

		old = atomic_cmpxchg_relaxed(&r->refs, val, new);
		if (old == val)
			break;

		val = old;
	}

	WARN_ONCE(new == UINT_MAX, "refcount_t: saturated; leaking memory.\n");

	return true;
}

/*
 * Similar to atomic_inc(), will saturate at UINT_MAX and WARN.
 *
 * Provides no memory ordering, it is assumed the caller already has a
 * reference on the object, will WARN when this is not so.
 */
static inline void refcount_inc(refcount_t *r)
{
	WARN_ONCE(!refcount_inc_not_zero(r), "refcount_t: increment on 0; use-after-free.\n");
}

/*
 * Similar to atomic_dec(), it will WARN on underflow and fail to decrement
 * when saturated at UINT_MAX.
 *
 * Provides release memory ordering, such that prior loads and stores are done
 * before.
 */

static inline void refcount_dec(refcount_t *r)
{
	WARN_ONCE(refcount_dec_and_test(r), "refcount_t: decrement hit 0; leaking memory.\n");
}

/*
 * No atomic_t counterpart, it attempts a 1 -> 0 transition and returns the
 * success thereof.
 *
 * Like all decrement operations, it provides release memory order and provides
 * a control dependency.
 *
 * It can be used like a try-delete operator; this explicit case is provided
 * and not cmpxchg in generic, because that would allow implementing unsafe
 * operations.
 */
static inline bool refcount_dec_if_one(refcount_t *r)
{
	return atomic_cmpxchg_release(&r->refs, 1, 0) == 1;
}

/**
 * Here we call kmalloc_array for mem allocate
 * Kernel optimize from 4.11
 */
#undef kvmalloc_array
#define kvmalloc_array _kc_kvmalloc_array
static inline void *_kc_kvmalloc_array(size_t n, size_t size, gfp_t flags)
{
	return kmalloc_array(n, size, flags);
}
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0))
#undef addrconf_addr_eui48_base
#define addrconf_addr_eui48_base _kc_addrconf_addr_eui48_base
static inline void _kc_addrconf_addr_eui48_base(u8 *eui,
						const char *const addr)
{
	memcpy(eui, addr, 3);
	eui[3] = 0xFF;
	eui[4] = 0xFE;
	memcpy(eui + 5, addr + 3, 3);
}

#undef addrconf_addr_eui48
#define addrconf_addr_eui48 _kc_addrconf_addr_eui48
static inline void _kc_addrconf_addr_eui48(u8 *eui, const char *const addr)
{
	addrconf_addr_eui48_base(eui, addr);
	eui[0] ^= 2;
}
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0))
#define is_signed_type(type)       (((type)(-1)) < (type)1)
#define __type_half_max(type) ((type)1 << (8*sizeof(type) - 1 - is_signed_type(type)))
#define type_max(T) ((T)((__type_half_max(T) - 1) + __type_half_max(T)))
#define type_min(T) ((T)((T)-type_max(T)-(T)1))

/*
 * If one of a or b is a compile-time constant, this avoids a division.
 */
#define __unsigned_mul_overflow(a, b, d) ({		\
	typeof(a) __a = (a);				\
	typeof(b) __b = (b);				\
	typeof(d) __d = (d);				\
	(void) (&__a == &__b);				\
	(void) (&__a == __d);				\
	*__d = __a * __b;				\
	__builtin_constant_p(__b) ?			\
	  __b > 0 && __a > type_max(typeof(__a)) / __b : \
	  __a > 0 && __b > type_max(typeof(__b)) / __a;	 \
})

/*
 * Signed multiplication is rather hard. gcc always follows C99, so
 * division is truncated towards 0. This means that we can write the
 * overflow check like this:
 *
 * (a > 0 && (b > MAX/a || b < MIN/a)) ||
 * (a < -1 && (b > MIN/a || b < MAX/a) ||
 * (a == -1 && b == MIN)
 *
 * The redundant casts of -1 are to silence an annoying -Wtype-limits
 * (included in -Wextra) warning: When the type is u8 or u16, the
 * __b_c_e in check_mul_overflow obviously selects
 * __unsigned_mul_overflow, but unfortunately gcc still parses this
 * code and warns about the limited range of __b.
 */

#define __signed_mul_overflow(a, b, d) ({				\
	typeof(a) __a = (a);						\
	typeof(b) __b = (b);						\
	typeof(d) __d = (d);						\
	typeof(a) __tmax = type_max(typeof(a));				\
	typeof(a) __tmin = type_min(typeof(a));				\
	(void) (&__a == &__b);						\
	(void) (&__a == __d);						\
	*__d = (u64)__a * (u64)__b;					\
	(__b > 0   && (__a > __tmax/__b || __a < __tmin/__b)) ||	\
	(__b < (typeof(__b))-1  && (__a > __tmin/__b || __a < __tmax/__b)) || \
	(__b == (typeof(__b))-1 && __a == __tmin);			\
})

#define check_mul_overflow(a, b, d)					\
	__builtin_choose_expr(is_signed_type(typeof(a)),		\
			__signed_mul_overflow(a, b, d),			\
			__unsigned_mul_overflow(a, b, d))

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0))
#define __must_check		__attribute__((warn_unused_result))

typedef unsigned long	__kernel_ulong_t;
typedef __kernel_ulong_t __kernel_size_t;
typedef __kernel_size_t		size_t;

#define SIZE_MAX	(~(size_t)0)
#endif

/**
 * array_size() - Calculate size of 2-dimensional array.
 *
 * @a: dimension one
 * @b: dimension two
 *
 * Calculates size of 2-dimensional array: @a * @b.
 *
 * Returns: number of bytes needed to represent the array or SIZE_MAX on
 * overflow.
 */
static inline __must_check size_t array_size(size_t a, size_t b)
{
	size_t bytes;

	if (check_mul_overflow(a, b, &bytes))
		return SIZE_MAX;

	return bytes;
}
#endif

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0))
#define CONFIG_NEW_KERNEL
#define MODIFY_CQ_MASK
#else
#endif

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4, 18, 0))
#define CONFIG_KERNEL_419
#endif

#endif /*_ROCE_K_COMPAT_H*/
