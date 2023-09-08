// SPDX-License-Identifier: GPL-2.0

#include <linux/pci.h>
#include <linux/syscore_ops.h>

#include <asm/hw_init.h>
#include <asm/sw64_init.h>

struct sw64_chip_ops *sw64_chip;
struct sw64_chip_init_ops *sw64_chip_init;

static int get_cpu_nums(void)
{
	unsigned long trkmode;
	int cpus;

	if (is_guest_or_emul())
		return 1;

	trkmode = sw64_io_read(0, TRKMODE);
	trkmode = (trkmode >> 6) & 0x3;
	cpus = 1 << trkmode;

	return cpus;
}

static unsigned long __init get_node_mem(int nodeid)
{
	unsigned long mc_config, mc_online, mc_cap, mc_num;
	unsigned long node_mem;

	if (is_guest_or_emul())
		return *(unsigned long *)MMSIZE & MMSIZE_MASK;

	mc_config = sw64_io_read(nodeid, MC_CAP_CFG) & 0xf;
	mc_cap = (1UL << mc_config) << 28;
	mc_online = sw64_io_read(nodeid, MC_ONLINE) & 0xff;
	mc_num = __kernel_ctpop(mc_online);
	node_mem = mc_cap * mc_num;

	return node_mem;
}

static void __init setup_core_start(struct cpumask *cpumask)
{
	int i, j, cpus;
	unsigned long coreonline;

	if (is_guest_or_emul()) {
		coreonline = sw64_io_read(0, CORE_ONLINE);
		for (i = 0; i < 64 ; i++) {
			if (coreonline & (1UL << i))
				cpumask_set_cpu(i, cpumask);
		}
	} else {
		cpus = get_cpu_nums();
		for (i = 0; i < cpus; i++) {
			coreonline = sw64_io_read(i, CORE_ONLINE);
			for (j = 0; j < 32 ; j++) {
				if (coreonline & (1UL << j))
					cpumask_set_cpu(i * 32 + j, cpumask);
			}
		}
	}
}

#ifdef CONFIG_PM
static void i2c_srst(void)
{
	sw64_io_write(0, I2C0_SRST_L, 0x0);
	sw64_io_write(0, I2C0_SRST_L, 0x1);

	sw64_io_write(0, I2C1_SRST_L, 0x0);
	sw64_io_write(0, I2C1_SRST_L, 0x1);

	sw64_io_write(0, I2C2_SRST_L, 0x0);
	sw64_io_write(0, I2C2_SRST_L, 0x1);
}

static void pcie_save(void)
{
	struct pci_controller *hose;
	struct piu_saved *piu_save;
	unsigned long node, index;
	unsigned long i;

	for (hose = hose_head; hose; hose = hose->next) {
		piu_save = kzalloc(sizeof(*piu_save), GFP_KERNEL);

		node = hose->node;
		index = hose->index;
		hose->sysdata = piu_save;

		piu_save->piuconfig0 = read_piu_ior0(node, index, PIUCONFIG0);
		piu_save->piuconfig1 = read_piu_ior1(node, index, PIUCONFIG1);
		piu_save->epdmabar = read_piu_ior0(node, index, EPDMABAR);
		piu_save->msiaddr = read_piu_ior0(node, index, MSIADDR);

		for (i = 0; i < 256; i++) {
			piu_save->msiconfig[i] = read_piu_ior0(node, index,
					MSICONFIG0 + (i << 7));
		}

		piu_save->iommuexcpt_ctrl = read_piu_ior0(node, index, IOMMUEXCPT_CTRL);
		piu_save->dtbaseaddr = read_piu_ior0(node, index, DTBASEADDR);

		piu_save->intaconfig = read_piu_ior0(node, index, INTACONFIG);
		piu_save->intbconfig = read_piu_ior0(node, index, INTBCONFIG);
		piu_save->intcconfig = read_piu_ior0(node, index, INTCCONFIG);
		piu_save->intdconfig = read_piu_ior0(node, index, INTDCONFIG);
		piu_save->pmeintconfig = read_piu_ior0(node, index, PMEINTCONFIG);
		piu_save->aererrintconfig = read_piu_ior0(node, index, AERERRINTCONFIG);
		piu_save->hpintconfig = read_piu_ior0(node, index, HPINTCONFIG);

	}
}

static void pcie_restore(void)
{
	struct pci_controller *hose;
	struct piu_saved *piu_save;
	unsigned long node, index;
	u32 rc_misc_ctrl;
	unsigned int value;
	unsigned long i;

	for (hose = hose_head; hose; hose = hose->next) {
		node = hose->node;
		index = hose->index;
		piu_save = hose->sysdata;

		write_piu_ior0(node, index, PIUCONFIG0, piu_save->piuconfig0);
		write_piu_ior1(node, index, PIUCONFIG1, piu_save->piuconfig1);
		write_piu_ior0(node, index, EPDMABAR, piu_save->epdmabar);
		write_piu_ior0(node, index, MSIADDR, piu_save->msiaddr);

		for (i = 0; i < 256; i++) {
			write_piu_ior0(node, index, MSICONFIG0 + (i << 7),
					piu_save->msiconfig[i]);
		}

		write_piu_ior0(node, index, IOMMUEXCPT_CTRL, piu_save->iommuexcpt_ctrl);
		write_piu_ior0(node, index, DTBASEADDR, piu_save->dtbaseaddr);

		write_piu_ior0(node, index, INTACONFIG, piu_save->intaconfig);
		write_piu_ior0(node, index, INTBCONFIG, piu_save->intbconfig);
		write_piu_ior0(node, index, INTCCONFIG, piu_save->intcconfig);
		write_piu_ior0(node, index, INTDCONFIG, piu_save->intdconfig);
		write_piu_ior0(node, index, PMEINTCONFIG, piu_save->pmeintconfig);
		write_piu_ior0(node, index, AERERRINTCONFIG, piu_save->aererrintconfig);
		write_piu_ior0(node, index, HPINTCONFIG, piu_save->hpintconfig);

		/* Enable DBI_RO_WR_EN */
		rc_misc_ctrl = read_rc_conf(node, index, RC_MISC_CONTROL_1);
		write_rc_conf(node, index, RC_MISC_CONTROL_1, rc_misc_ctrl | 0x1);

		/* Fix up DEVICE_ID_VENDOR_ID register */
		value = (PCI_DEVICE_ID_CHIP3 << 16) | PCI_VENDOR_ID_JN;
		write_rc_conf(node, index, RC_VENDOR_ID, value);

		/* Set PCI-E root class code */
		value = read_rc_conf(node, index, RC_REVISION_ID);
		write_rc_conf(node, index, RC_REVISION_ID, (PCI_CLASS_BRIDGE_HOST << 16) | value);

		/* Disable DBI_RO_WR_EN */
		write_rc_conf(node, index, RC_MISC_CONTROL_1, rc_misc_ctrl);
	}

}

static unsigned long saved_dvc_int, saved_long_time;

static inline void intpu_save(void)
{
	saved_long_time = sw64_io_read(0, LONG_TIME);
}

static inline void intpu_restore(void)
{
	switch (cpu_desc.model) {
	case CPU_SW831:
		sw64_io_write(0, LONG_TIME, saved_long_time);
		sw64_io_write(0, LONG_TIME_START_EN, 0x1);
		break;
	default:
		pr_info("long time start is disable!");
		break;
	}
}

static inline void spbu_save(void)
{
	saved_dvc_int = sw64_io_read(0, MCU_DVC_INT_EN);
}

static inline void spbu_restore(void)
{
	i2c_srst();
	sw64_io_write(0, MCU_DVC_INT_EN, saved_dvc_int);
}

static int io_suspend(void)
{
	spbu_save();
	intpu_save();
	pcie_save();

	return 0;
}

static void io_resume(void)
{
	pcie_restore();
	intpu_restore();
	spbu_restore();
}
#endif /* CONFIG_PM */

static struct sw64_chip_init_ops chip_init_ops = {
	.early_init = {
		.setup_core_start = setup_core_start,
		.get_node_mem = get_node_mem,
	},
};

static struct sw64_chip_ops chip_ops = {
	.get_cpu_num = get_cpu_nums,
};

void __init setup_chip_ops(void)
{
	sw64_chip_init = &chip_init_ops;
	sw64_chip = &chip_ops;
	setup_chip_pci_ops();
#ifdef CONFIG_PM
	io_syscore_ops.suspend = io_suspend;
	io_syscore_ops.resume = io_resume;
#endif
}
