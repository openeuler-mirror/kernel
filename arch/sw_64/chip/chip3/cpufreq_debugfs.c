// SPDX-License-Identifier: GPL-2.0

#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/uaccess.h>

#include <asm/sw64io.h>
#include <asm/debug.h>

#define CLK_PRT		0x1UL
#define CORE_CLK0_V	(0x1UL << 1)
#define CORE_CLK0_R	(0x1UL << 2)
#define CORE_CLK2_V	(0x1UL << 15)
#define CORE_CLK2_R	(0x1UL << 16)

#define CLK_LV1_SEL_PRT		0x1UL
#define CLK_LV1_SEL_MUXA	(0x1UL << 2)
#define CLK_LV1_SEL_MUXB	(0x1UL << 3)

#define CORE_PLL0_CFG_SHIFT	4
#define CORE_PLL2_CFG_SHIFT	18

static int cpu_freq[16] = {
	200,	1200,	1800,	1900,
	1950,	2000,	2050,	2100,
	2150,	2200,	2250,	2300,
	2350,	2400,	2450,	2500
};

static int cpufreq_show(struct seq_file *m, void *v)
{
	int i;
	u64 val;

	val = sw64_io_read(0, CLK_CTL);
	val = val >> CORE_PLL2_CFG_SHIFT;

	for (i = 0; i < sizeof(cpu_freq)/sizeof(int); i++) {
		if (cpu_freq[val] == cpu_freq[i])
			seq_printf(m, "[%d] ", cpu_freq[i]);
		else
			seq_printf(m, "%d ", cpu_freq[i]);
	}
	seq_puts(m, "\n");

	return 0;
}

static int cpufreq_open(struct inode *inode, struct file *file)
{
	return single_open(file, cpufreq_show, NULL);
}

static ssize_t cpufreq_set(struct file *file, const char __user *user_buf,
			size_t len, loff_t *ppos)
{
	char buf[5];
	size_t size;
	int cf, i, err, index;
	u64 val;

	size = min(sizeof(buf) - 1, len);
	if (copy_from_user(buf, user_buf, size))
		return -EFAULT;
	buf[size] = '\0';

	err = kstrtoint(buf, 10, &cf);
	if (err)
		return err;

	index = -1;
	for (i = 0; i < sizeof(cpu_freq)/sizeof(int); i++) {
		if (cf == cpu_freq[i]) {
			index = i;
			break;
		}
	}

	if (index < 0)
		return -EINVAL;

	/* Set CLK_CTL PLL2 */
	sw64_io_write(0, CLK_CTL, CORE_CLK2_R | CORE_CLK2_V | CLK_PRT);
	sw64_io_write(1, CLK_CTL, CORE_CLK2_R | CORE_CLK2_V | CLK_PRT);
	val = sw64_io_read(0, CLK_CTL);

	sw64_io_write(0, CLK_CTL, val | index << CORE_PLL2_CFG_SHIFT);
	sw64_io_write(1, CLK_CTL, val | index << CORE_PLL2_CFG_SHIFT);

	udelay(1);

	sw64_io_write(0, CLK_CTL, CORE_CLK2_V | CLK_PRT
			| index << CORE_PLL2_CFG_SHIFT);
	sw64_io_write(1, CLK_CTL, CORE_CLK2_V | CLK_PRT
			| index << CORE_PLL2_CFG_SHIFT);
	val = sw64_io_read(0, CLK_CTL);

	/* LV1 select PLL1/PLL2 */
	sw64_io_write(0, CLU_LV1_SEL, CLK_LV1_SEL_MUXA | CLK_LV1_SEL_PRT);
	sw64_io_write(1, CLU_LV1_SEL, CLK_LV1_SEL_MUXA | CLK_LV1_SEL_PRT);

	/* Set CLK_CTL PLL0 */
	sw64_io_write(0, CLK_CTL, val | CORE_CLK0_R | CORE_CLK0_V);
	sw64_io_write(1, CLK_CTL, val | CORE_CLK0_R | CORE_CLK0_V);

	sw64_io_write(0, CLK_CTL, val | CORE_CLK0_R | CORE_CLK0_V
			| index << CORE_PLL0_CFG_SHIFT);
	sw64_io_write(1, CLK_CTL, val | CORE_CLK0_R | CORE_CLK0_V
			| index << CORE_PLL0_CFG_SHIFT);

	udelay(1);

	sw64_io_write(0, CLK_CTL, val | CORE_CLK0_V
			| index << CORE_PLL0_CFG_SHIFT);
	sw64_io_write(1, CLK_CTL, val | CORE_CLK0_V
			| index << CORE_PLL0_CFG_SHIFT);

	/* LV1 select PLL0/PLL1 */
	sw64_io_write(0, CLU_LV1_SEL, CLK_LV1_SEL_MUXB | CLK_LV1_SEL_PRT);
	sw64_io_write(1, CLU_LV1_SEL, CLK_LV1_SEL_MUXB | CLK_LV1_SEL_PRT);

	return len;
}

static const struct file_operations set_cpufreq_fops = {
	.open		= cpufreq_open,
	.read		= seq_read,
	.write		= cpufreq_set,
	.llseek         = seq_lseek,
	.release        = single_release,
};

static int __init cpufreq_debugfs_init(void)
{
	struct dentry *cpufreq_entry;

	if (!sw64_debugfs_dir)
		return -ENODEV;

	cpufreq_entry = debugfs_create_file("cpufreq", 0600,
				       sw64_debugfs_dir, NULL,
				       &set_cpufreq_fops);
	if (!cpufreq_entry)
		return -ENOMEM;

	return 0;
}
late_initcall(cpufreq_debugfs_init);
