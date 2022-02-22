/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_SW64IO_H
#define _ASM_SW64_SW64IO_H

#include <asm/page.h>

extern void setup_chip_clocksource(void);

#if defined(CONFIG_SW64_CHIP3)
#include <asm/chip3_io.h>
#endif

#define MK_RC_CFG(nid, idx) \
	(PAGE_OFFSET | SW64_PCI_IO_BASE((nid), (idx)) | PCI_RC_CFG)
#define MK_PIU_IOR0(nid, idx) \
	(PAGE_OFFSET | SW64_PCI_IO_BASE((nid), (idx)) | PCI_IOR0_BASE)
#define MK_PIU_IOR1(nid, idx) \
	(PAGE_OFFSET | SW64_PCI_IO_BASE((nid), (idx)) | PCI_IOR1_BASE)

static inline  unsigned int
read_rc_conf(unsigned long node, unsigned long rc_index,
		unsigned int conf_offset)
{
	unsigned long addr;
	unsigned int value;

	addr = MK_RC_CFG(node, rc_index) | conf_offset;
	value = *(volatile unsigned int *)addr;
	mb();

	return value;
}

static inline void
write_rc_conf(unsigned long node, unsigned long rc_index,
		unsigned int conf_offset, unsigned int data)
{
	unsigned long addr;

	addr = MK_RC_CFG(node, rc_index) | conf_offset;
	*(unsigned int *)addr = data;
	mb();
}

static inline  unsigned long
read_piu_ior0(unsigned long node, unsigned long rc_index,
		unsigned int reg)
{
	unsigned long addr;
	unsigned long value;

	addr = MK_PIU_IOR0(node, rc_index) + reg;
	value = *(volatile unsigned long __iomem *)addr;
	mb();

	return value;
}

static inline void
write_piu_ior0(unsigned long node, unsigned long rc_index,
		unsigned int reg, unsigned long data)
{
	unsigned long addr;

	addr = MK_PIU_IOR0(node, rc_index) + reg;
	*(unsigned long __iomem *)addr = data;
	mb();
}

static inline  unsigned long
read_piu_ior1(unsigned long node, unsigned long rc_index,
		unsigned int reg)
{
	unsigned long addr, value;

	addr = MK_PIU_IOR1(node, rc_index) + reg;
	value = *(volatile unsigned long __iomem *)addr;
	mb();

	return value;
}

static inline void
write_piu_ior1(unsigned long node, unsigned long rc_index,
		unsigned int reg, unsigned long data)
{
	unsigned long addr;

	addr = MK_PIU_IOR1(node, rc_index) + reg;
	*(volatile unsigned long __iomem *)addr = data;
	mb();
}

static inline unsigned long
sw64_io_read(unsigned long node, unsigned long reg)
{
	unsigned long addr, value;

	addr = PAGE_OFFSET | SW64_IO_BASE(node) | reg;
	value = *(volatile unsigned long __iomem *)addr;
	mb();

	return value;
}

static inline void
sw64_io_write(unsigned long node, unsigned long reg, unsigned long data)
{
	unsigned long addr;

	addr = PAGE_OFFSET | SW64_IO_BASE(node) | reg;
	*(volatile unsigned long __iomem *)addr = data;
	mb();
}
#endif
