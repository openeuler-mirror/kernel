/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2017 Hisilicon Limited. */

#ifndef _KCOMPAT_H_
#define _KCOMPAT_H_

#include <linux/pci.h>
#include <linux/msi.h>
#include <net/pkt_cls.h>
#include <linux/compiler.h>

#ifndef LINUX_VERSION_CODE
#include <linux/version.h>
#else
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))
#endif

#ifndef PCI_VENDOR_ID_HUAWEI
#define PCI_VENDOR_ID_HUAWEI	0x19e5
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0))
#undef mdiobus_get_phy
#define mdiobus_get_phy _kc_mdiobus_get_phy

static inline
struct phy_device *_kc_mdiobus_get_phy(struct mii_bus *bus, int addr)
{
	struct phy_device *phydev = bus->phy_map[addr];

	if (!phydev)
		return NULL;

	return phydev;
}

#endif /* 4.5.0 */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0))
#undef csum_replace_by_diff
#define csum_replace_by_diff _kc_csum_replace_by_diff

static inline void _kc_csum_replace_by_diff(__sum16 *sum, __wsum diff)
{
	*sum = csum_fold(csum_add(diff, ~csum_unfold(*sum)));
}

#else
#define HAVE_ETHTOOL_IPV6_NFC_API
#endif /* 4.6.0 */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0))

#undef phy_ethtool_ksettings_get
#define phy_ethtool_ksettings_get _kc_phy_ethtool_ksettings_get

/* Hi1980 IO have no external phy devices, so just return not support */
static inline int _kc_phy_ethtool_ksettings_get(struct phy_device *phydev,
			      const struct ethtool_link_ksettings *cmd)
{
	return -EOPNOTSUPP;
}

#undef phy_ethtool_ksettings_set
#define phy_ethtool_ksettings_set _kc_phy_ethtool_ksettings_set
static inline int _kc_phy_ethtool_ksettings_set(struct phy_device *phydev,
			      const struct ethtool_link_ksettings *cmd)
{
	return -EOPNOTSUPP;
}

#else

#define HAVE_ETHTOOL_CONVERT_U32_AND_LINK_MODE
#endif /* 4.7.0 */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0))
static inline void
pci_release_mem_regions(struct pci_dev *pdev)
{
	return pci_release_selected_regions(pdev,
			    pci_select_bars(pdev, IORESOURCE_MEM));
}

#define PCI_IRQ_LEGACY		(1 << 0) /* Allow legacy interrupts */
#define PCI_IRQ_MSI		(1 << 1) /* Allow MSI interrupts */
#define PCI_IRQ_MSIX		(1 << 2) /* Allow MSI-X interrupts */
#define PCI_IRQ_AFFINITY		(1 << 3) /* Auto-assign affinity */
#define PCI_IRQ_ALL_TYPES \
	(PCI_IRQ_LEGACY | PCI_IRQ_MSI | PCI_IRQ_MSIX)

#undef pci_free_irq_vectors
#define pci_free_irq_vectors _kc_pci_free_irq_vectors

#undef pci_irq_vector
#define pci_irq_vector _kc_pci_irq_vector

#undef pci_alloc_irq_vectors
#define pci_alloc_irq_vectors _kc_pci_alloc_irq_vectors

void _kc_pci_free_irq_vectors(struct pci_dev *dev);

int _kc_pci_irq_vector(struct pci_dev *dev, unsigned int nr);

int _kc_pci_alloc_irq_vectors(struct pci_dev *dev, unsigned int min_vecs,
		      unsigned int max_vecs, unsigned int flags);

#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0))
#else
#define HAVE_NETDEVICE_MIN_MAX_MTU
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0))
#else /* >= 4.11 */
#define HAVE_VOID_NDO_GET_STATS64
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0))
#else /* >= 4.13 */
#define SKB_PUT_RETURN_VOID_POINT
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0))
#define TIMER_DATA_TYPE		unsigned long
#define TIMER_FUNC_TYPE		void (*)(TIMER_DATA_TYPE)

#define timer_setup(timer, callback, flags)				\
	__setup_timer((timer), (TIMER_FUNC_TYPE)(callback),		\
		      (TIMER_DATA_TYPE)(timer), (flags))

#define from_timer(var, callback_timer, timer_fieldname) \
	container_of(callback_timer, typeof(*var), timer_fieldname)

#else
#define HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0))
static inline void cpu_to_be32_array(__be32 *dst, const u32 *src, size_t len)
{
	int i;

	for (i = 0; i < len; i++)
		dst[i] = cpu_to_be32(src[i]);
}

static inline void be32_to_cpu_array(u32 *dst, const __be32 *src, size_t len)
{
	int i;

	for (i = 0; i < len; i++)
		dst[i] = be32_to_cpu(src[i]);
}

#define TC_SETUP_QDISC_MQPRIO TC_SETUP_MQPRIO

/* MQPRIO */
#define TC_QOPT_BITMASK 15
#define TC_QOPT_MAX_QUEUE 16

enum {
	TC_MQPRIO_MODE_DCB,
	TC_MQPRIO_MODE_CHANNEL,
	__TC_MQPRIO_MODE_MAX
};

struct tc_mqprio_qopt_offload {
	/* struct tc_mqprio_qopt must always be the first element */
	struct tc_mqprio_qopt qopt;
	u16 mode;
	u16 shaper;
	u32 flags;
	u64 min_rate[TC_QOPT_MAX_QUEUE];
	u64 max_rate[TC_QOPT_MAX_QUEUE];
};

#else
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0))

#define is_signed_type(type)       (((type)(-1)) < (type)1)
#define __type_half_max(type) ((type)1 << (8*sizeof(type) - 1 \
			      - is_signed_type(type)))
#define type_max(T) ((T)((__type_half_max(T) - 1) + __type_half_max(T)))
#define type_min(T) ((T)((T)-type_max(T)-(T)1))

#ifdef COMPILER_HAS_GENERIC_BUILTIN_OVERFLOW
/*
 * For simplicity and code hygiene, the fallback code below insists on
 * a, b and *d having the same type (similar to the min() and max()
 * macros), whereas gcc's type-generic overflow checkers accept
 * different types. Hence we don't just make check_add_overflow an
 * alias for __builtin_add_overflow, but add type checks similar to
 * below.
 */
#define check_add_overflow(a, b, d) ({		\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	__builtin_add_overflow(__a, __b, __d);	\
})

#define check_sub_overflow(a, b, d) ({		\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	__builtin_sub_overflow(__a, __b, __d);	\
})

#define check_mul_overflow(a, b, d) ({		\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	__builtin_mul_overflow(__a, __b, __d);	\
})

#else

/* Checking for unsigned overflow is relatively easy without causing UB. */
#define __unsigned_add_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	*__d = __a + __b;			\
	*__d < __a;				\
})
#define __unsigned_sub_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	*__d = __a - __b;			\
	__a < __b;				\
})
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
 * For signed types, detecting overflow is much harder, especially if
 * we want to avoid UB. But the interface of these macros is such that
 * we must provide a result in *d, and in fact we must produce the
 * result promised by gcc's builtins, which is simply the possibly
 * wrapped-around value. Fortunately, we can just formally do the
 * operations in the widest relevant unsigned type (u64) and then
 * truncate the result - gcc is smart enough to generate the same code
 * with and without the (u64) casts.
 */

/*
 * Adding two signed integers can overflow only if they have the same
 * sign, and overflow has happened iff the result has the opposite
 * sign.
 */
#define __signed_add_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	*__d = (u64)__a + (u64)__b;		\
	(((~(__a ^ __b)) & (*__d ^ __a))	\
		& type_min(typeof(__a))) != 0;	\
})

/*
 * Subtraction is similar, except that overflow can now happen only
 * when the signs are opposite. In this case, overflow has happened if
 * the result has the opposite sign of a.
 */
#define __signed_sub_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	*__d = (u64)__a - (u64)__b;		\
	((((__a ^ __b)) & (*__d ^ __a))		\
		& type_min(typeof(__a))) != 0;	\
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


#define check_add_overflow(a, b, d)					\
	__builtin_choose_expr(is_signed_type(typeof(a)),		\
			__signed_add_overflow(a, b, d),			\
			__unsigned_add_overflow(a, b, d))

#define check_sub_overflow(a, b, d)					\
	__builtin_choose_expr(is_signed_type(typeof(a)),		\
			__signed_sub_overflow(a, b, d),			\
			__unsigned_sub_overflow(a, b, d))

#define check_mul_overflow(a, b, d)					\
	__builtin_choose_expr(is_signed_type(typeof(a)),		\
			__signed_mul_overflow(a, b, d),			\
			__unsigned_mul_overflow(a, b, d))


#endif /* COMPILER_HAS_GENERIC_BUILTIN_OVERFLOW */

#ifndef array3_size
/**
 * array3_size() - Calculate size of 3-dimensional array.
 *
 * @a: dimension one
 * @b: dimension two
 * @c: dimension three
 *
 * Calculates size of 3-dimensional array: @a * @b * @c.
 *
 * Returns: number of bytes needed to represent the array or SIZE_MAX on
 * overflow.
 */
static inline __must_check size_t array3_size(size_t a, size_t b, size_t c)
{
	size_t bytes;

	if (check_mul_overflow(a, b, &bytes))
		return SIZE_MAX;
	if (check_mul_overflow(bytes, c, &bytes))
		return SIZE_MAX;

	return bytes;
}
#endif
#else
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 4))

#include <linux/bitmap.h>

static inline void linkmode_set_bit(int nr, volatile unsigned long *addr)
{
	__set_bit(nr, addr);
}

static inline void linkmode_copy(unsigned long *dst, const unsigned long *src)
{
	bitmap_copy(dst, src, __ETHTOOL_LINK_MODE_MASK_NBITS);
}

static inline void linkmode_clear_bit(int nr, volatile unsigned long *addr)
{
	__clear_bit(nr, addr);
}

static inline void linkmode_zero(unsigned long *dst)
{
	bitmap_zero(dst, __ETHTOOL_LINK_MODE_MASK_NBITS);
}

#else

#define HAS_LINK_MODE_OPS

#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0))
#ifndef ETH_MODULE_SFF_8636_MAX_LEN
#define ETH_MODULE_SFF_8636_MAX_LEN	640
#endif

#ifndef ETH_MODULE_SFF_8436_MAX_LEN
#define ETH_MODULE_SFF_8436_MAX_LEN	640
#endif
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0))
#ifndef dma_zalloc_coherent
#define dma_zalloc_coherent(d, s, h, f) dma_alloc_coherent(d, s, h, f)
#endif
#endif

#endif
