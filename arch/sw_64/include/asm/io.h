/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_IO_H
#define _ASM_SW64_IO_H

#ifdef __KERNEL__

#include <linux/kernel.h>
#include <linux/mm.h>
#include <asm/compiler.h>
#include <asm/pgtable.h>

/* The generic header contains only prototypes.  Including it ensures that
 * the implementation we have here matches that interface.
 */
#include <asm-generic/iomap.h>

/* We don't use IO slowdowns on the sw64, but.. */
#define __SLOW_DOWN_IO	do { } while (0)
#define SLOW_DOWN_IO	do { } while (0)

/*
 * Change virtual addresses to physical addresses and vv.
 */
static inline unsigned long virt_to_phys(void *address)
{
	return __pa(address);
}

static inline void *phys_to_virt(unsigned long address)
{
	return __va(address);
}

#define page_to_phys(page)	page_to_pa(page)

/* Maximum PIO space address supported?  */
#define IO_SPACE_LIMIT		0xffffffffffffffff

/*
 * Change addresses as seen by the kernel (virtual) to addresses as
 * seen by a device (bus), and vice versa.
 *
 * Note that this only works for a limited range of kernel addresses,
 * and very well may not span all memory.  Consider this interface
 * deprecated in favour of the DMA-mapping API.
 */

static inline unsigned long __deprecated virt_to_bus(void *address)
{
	return virt_to_phys(address);
}
#define isa_virt_to_bus virt_to_bus

static inline void * __deprecated bus_to_virt(unsigned long address)
{
	void *virt;

	/* This check is a sanity check but also ensures that bus address 0
	 * maps to virtual address 0 which is useful to detect null pointers
	 * (the NCR driver is much simpler if NULL pointers are preserved).
	 */
	virt = phys_to_virt(address);
	return (long)address <= 0 ? NULL : virt;
}
#define isa_bus_to_virt bus_to_virt

/*
 * Generic IO read/write.  These perform native-endian accesses.
 */

#define __raw_writeb __raw_writeb
static inline void __raw_writeb(u8 val, volatile void __iomem *addr)
{
	asm volatile("stb %0, 0(%1)" : : "r" (val), "r" (addr));
}

#define __raw_writew __raw_writew
static inline void __raw_writew(u16 val, volatile void __iomem *addr)
{
	asm volatile("sth %0, 0(%1)" : : "r" (val), "r" (addr));
}

#define __raw_writel __raw_writel
static inline void __raw_writel(u32 val, volatile void __iomem *addr)
{
	asm volatile("stw %0, 0(%1)" : : "r" (val), "r" (addr));
}

#define __raw_writeq __raw_writeq
static inline void __raw_writeq(u64 val, volatile void __iomem *addr)
{
	asm volatile("stl %0, 0(%1)" : : "r" (val), "r" (addr));
}

#define __raw_readb __raw_readb
static inline u8 __raw_readb(const volatile void __iomem *addr)
{
	u8 val;

	asm volatile("ldbu %0, 0(%1)" : "=r" (val) : "r" (addr));
	return val;
}

#define __raw_readw __raw_readw
static inline u16 __raw_readw(const volatile void __iomem *addr)
{
	u16 val;

	asm volatile("ldhu %0, 0(%1)" : "=r" (val) : "r" (addr));
	return val;
}

#define __raw_readl __raw_readl
static inline u32 __raw_readl(const volatile void __iomem *addr)
{
	u32 val;

	asm volatile("ldw	%0, 0(%1)\n"
		     "zapnot	%0, 0xf, %0\n"
		     : "=r" (val) : "r" (addr));
	return val;
}

#define __raw_readq __raw_readq
static inline u64 __raw_readq(const volatile void __iomem *addr)
{
	u64 val;

	asm volatile("ldl %0, 0(%1)" : "=r" (val) : "r" (addr));
	return val;
}

/* IO barriers */

#define __iormb()		rmb()
#define __iowmb()		wmb()
#define mmiowb()		do { } while (0)

/*
 * Relaxed I/O memory access primitives. These follow the Device memory
 * ordering rules but do not guarantee any ordering relative to Normal memory
 * accesses.
 */
#define readb_relaxed(c)	__raw_readb(c)
#define readw_relaxed(c)	__raw_readw(c)
#define readl_relaxed(c)	__raw_readl(c)
#define readq_relaxed(c)	__raw_readq(c)

#define writeb_relaxed(v, c)	__raw_writeb((v), (c))
#define writew_relaxed(v, c)	__raw_writew((v), (c))
#define writel_relaxed(v, c)	__raw_writel((v), (c))
#define writeq_relaxed(v, c)	__raw_writeq((v), (c))

/*
 * I/O memory access primitives. Reads are ordered relative to any
 * following Normal memory access. Writes are ordered relative to any prior
 * Normal memory access.
 */
#define readb(c)		({ u8  __v = readb_relaxed(c); __iormb(); __v; })
#define readw(c)		({ u16 __v = readw_relaxed(c); __iormb(); __v; })
#define readl(c)		({ u32 __v = readl_relaxed(c); __iormb(); __v; })
#define readq(c)		({ u64 __v = readq_relaxed(c); __iormb(); __v; })

#define writeb(v, c)		({ __iowmb(); writeb_relaxed((v), (c)); })
#define writew(v, c)		({ __iowmb(); writew_relaxed((v), (c)); })
#define writel(v, c)		({ __iowmb(); writel_relaxed((v), (c)); })
#define writeq(v, c)		({ __iowmb(); writeq_relaxed((v), (c)); })
/*
 * We always have external versions of these routines.
 */
extern u8		inb(unsigned long port);
extern u16		inw(unsigned long port);
extern u32		inl(unsigned long port);
extern void		outb(u8 b, unsigned long port);
extern void		outw(u16 b, unsigned long port);
extern void		outl(u32 b, unsigned long port);

static inline void __iomem *__ioremap(phys_addr_t addr, size_t size,
				      pgprot_t prot)
{
	unsigned long tmp = addr | PAGE_OFFSET;

	return (void __iomem *)(tmp);
}

#define ioremap(addr, size)		__ioremap((addr), (size), PAGE_KERNEL)
#define ioremap_nocache(addr, size)	__ioremap((addr), (size), PAGE_KERNEL)
#define ioremap_cache(addr, size)	__ioremap((addr), (size), PAGE_KERNEL)
#define ioremap_uc			ioremap_nocache

static inline void __iounmap(volatile void __iomem *addr)
{
}

#define iounmap				__iounmap

#define ioread16be(p) be16_to_cpu(ioread16(p))
#define ioread32be(p) be32_to_cpu(ioread32(p))
#define iowrite16be(v, p) iowrite16(cpu_to_be16(v), (p))
#define iowrite32be(v, p) iowrite32(cpu_to_be32(v), (p))

#define inb_p		inb
#define inw_p		inw
#define inl_p		inl
#define outb_p		outb
#define outw_p		outw
#define outl_p		outl


/*
 * String version of IO memory access ops:
 */
extern void memcpy_fromio(void *, const volatile void __iomem *, long);
extern void memcpy_toio(volatile void __iomem *, const void *, long);
extern void _memset_c_io(volatile void __iomem *, unsigned long, long);

static inline void memset_io(volatile void __iomem *addr, u8 c, long len)
{
	_memset_c_io(addr, 0x0101010101010101UL * c, len);
}

#define __HAVE_ARCH_MEMSETW_IO
static inline void memsetw_io(volatile void __iomem *addr, u16 c, long len)
{
	_memset_c_io(addr, 0x0001000100010001UL * c, len);
}

/*
 * String versions of in/out ops:
 */
extern void insb(unsigned long port, void *dst, unsigned long count);
extern void insw(unsigned long port, void *dst, unsigned long count);
extern void insl(unsigned long port, void *dst, unsigned long count);
extern void outsb(unsigned long port, const void *src, unsigned long count);
extern void outsw(unsigned long port, const void *src, unsigned long count);
extern void outsl(unsigned long port, const void *src, unsigned long count);

/*
 * These defines will override the defaults when doing RTC queries
 */

#define RTC_PORT(x)	(0x70 + (x))
#define RTC_ALWAYS_BCD	0

/*
 * Convert a physical pointer to a virtual kernel pointer for /dev/mem
 * access
 */
#define xlate_dev_mem_ptr(p)	__va(p)

/*
 * Convert a virtual cached pointer to an uncached pointer
 */
#define xlate_dev_kmem_ptr(p)	p

#endif /* __KERNEL__ */

#endif /* _ASM_SW64_IO_H */
