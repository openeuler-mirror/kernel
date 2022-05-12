/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_SW64IO_H
#define _ASM_SW64_SW64IO_H

#include <asm/page.h>

extern void setup_chip_clocksource(void);

#if defined(CONFIG_SW64_CHIP3)
#include <asm/chip3_io.h>
#endif

#define MK_RC_CFG(nid, idx) \
	(SW64_PCI_IO_BASE((nid), (idx)) | PCI_RC_CFG)
#define MK_PIU_IOR0(nid, idx) \
	(SW64_PCI_IO_BASE((nid), (idx)) | PCI_IOR0_BASE)
#define MK_PIU_IOR1(nid, idx) \
	(SW64_PCI_IO_BASE((nid), (idx)) | PCI_IOR1_BASE)

static inline  unsigned int
read_rc_conf(unsigned long node, unsigned long rc,
		unsigned int offset)
{
	void __iomem *addr;
	unsigned int value;

	addr = __va(MK_RC_CFG(node, rc) | offset);
	value = *(volatile unsigned int *)addr;
	mb();

	return value;
}

static inline void
write_rc_conf(unsigned long node, unsigned long rc,
		unsigned int offset, unsigned int data)
{
	void __iomem *addr;

	addr = __va(MK_RC_CFG(node, rc) | offset);
	*(unsigned int *)addr = data;
	mb();
}

static inline  unsigned long
read_piu_ior0(unsigned long node, unsigned long rc,
		unsigned int reg)
{
	void __iomem *addr;
	unsigned long value;

	addr = __va(MK_PIU_IOR0(node, rc) + reg);
	value = *(volatile unsigned long __iomem *)addr;
	mb();

	return value;
}

static inline void
write_piu_ior0(unsigned long node, unsigned long rc,
		unsigned int reg, unsigned long data)
{
	void __iomem *addr;

	addr = __va(MK_PIU_IOR0(node, rc) + reg);
	*(unsigned long __iomem *)addr = data;
	mb();
}

static inline  unsigned long
read_piu_ior1(unsigned long node, unsigned long rc,
		unsigned int reg)
{
	void __iomem *addr;
	unsigned long value;

	addr = __va(MK_PIU_IOR1(node, rc) + reg);
	value = *(volatile unsigned long __iomem *)addr;
	mb();

	return value;
}

static inline void
write_piu_ior1(unsigned long node, unsigned long rc,
		unsigned int reg, unsigned long data)
{
	void __iomem *addr;

	addr = __va(MK_PIU_IOR1(node, rc) + reg);
	*(volatile unsigned long __iomem *)addr = data;
	mb();
}

static inline unsigned long
sw64_io_read(unsigned long node, unsigned long reg)
{
	void __iomem *addr;
	unsigned long value;

	addr = __va(SW64_IO_BASE(node) | reg);
	value = *(volatile unsigned long __iomem *)addr;
	mb();

	return value;
}

static inline void
sw64_io_write(unsigned long node, unsigned long reg, unsigned long data)
{
	void __iomem *addr;

	addr = __va(SW64_IO_BASE(node) | reg);
	*(volatile unsigned long __iomem *)addr = data;
	mb();
}
#endif
