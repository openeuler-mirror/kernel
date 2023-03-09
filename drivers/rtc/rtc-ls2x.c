// SPDX-License-Identifier: GPL-2.0
/*
 * Loongson-2K/7A RTC driver
 *
 * Based on the original out-of-tree Loongson-2H RTC driver for Linux 2.6.32,
 * by Shaozong Liu <liushaozong@loongson.cn>.
 *
 * Maintained out-of-tree by Huacai Chen <chenhuacai@kernel.org>.
 *
 * Rewritten for mainline by WANG Xuerui <git@xen0n.name>.
 */

#include <linux/of.h>
#include <linux/rtc.h>
#include <linux/acpi.h>
#include <linux/regmap.h>
#include <linux/module.h>
#include <linux/bitfield.h>
#include <linux/platform_device.h>

#define TOY_TRIM_REG	0x20
#define TOY_WRITE0_REG	0x24
#define TOY_WRITE1_REG	0x28
#define TOY_READ0_REG	0x2c
#define TOY_READ1_REG	0x30
#define TOY_MATCH0_REG	0x34
#define TOY_MATCH1_REG	0x38
#define TOY_MATCH2_REG	0x3c
#define RTC_CTRL_REG	0x40
#define RTC_TRIM_REG	0x60
#define RTC_WRITE0_REG	0x64
#define RTC_READ0_REG	0x68
#define RTC_MATCH0_REG	0x6c
#define RTC_MATCH1_REG	0x70
#define RTC_MATCH2_REG	0x74

#define TOY_MON		GENMASK(31, 26)
#define TOY_DAY		GENMASK(25, 21)
#define TOY_HOUR	GENMASK(20, 16)
#define TOY_MIN		GENMASK(15, 10)
#define TOY_SEC		GENMASK(9, 4)
#define TOY_MSEC	GENMASK(3, 0)

#define TOY_MATCH_YEAR	GENMASK(31, 26)
#define TOY_MATCH_MON	GENMASK(25, 22)
#define TOY_MATCH_DAY	GENMASK(21, 17)
#define TOY_MATCH_HOUR	GENMASK(16, 12)
#define TOY_MATCH_MIN	GENMASK(11, 6)
#define TOY_MATCH_SEC	GENMASK(5, 0)

/* ACPI and RTC offset */
#define ACPI_RTC_OFFSET		0x100

/* support rtc wakeup */
#define ACPI_PM1_STS_REG	0x0c
#define ACPI_PM1_EN_REG		0x10
#define RTC_EN			BIT(10)
#define RTC_STS 		BIT(10)

struct ls2x_rtc_priv {
	struct regmap *regmap;
	spinlock_t rtc_reglock;
	void __iomem *acpi_base;
	struct rtc_device *rtcdev;
};

static const struct regmap_config ls2x_rtc_regmap_config = {
	.reg_bits = 32,
	.val_bits = 32,
	.reg_stride = 4,
};

struct ls2x_rtc_regs {
	u32 reg0;
	u32 reg1;
};

#if defined(CONFIG_ACPI)
static u32 ls2x_acpi_fix_handler(void *id)
{
	int ret;
	struct ls2x_rtc_priv *priv = (struct ls2x_rtc_priv *)id;

	spin_lock(&priv->rtc_reglock);

	/* Disable acpi rtc enabled */
	ret = readl(priv->acpi_base + ACPI_PM1_EN_REG) & ~RTC_EN;
	writel(ret, priv->acpi_base + ACPI_PM1_EN_REG);

	/* Clear acpi rtc interrupt Status */
	writel(RTC_STS, priv->acpi_base + ACPI_PM1_STS_REG);

	spin_unlock(&priv->rtc_reglock);

	/*
	 * The TOY_MATCH0_REG should be cleared 0 here,
	 * otherwise the interrupt cannot be cleared.
	 * Because the match condition is still satisfied
	 */
	ret = regmap_write(priv->regmap, TOY_MATCH0_REG, 0);
	if (unlikely(ret))
		return ret;

	return 0;
}
#endif

static inline void ls2x_rtc_regs_to_time(struct ls2x_rtc_regs *regs,
					 struct rtc_time *tm)
{
	tm->tm_year = regs->reg1;
	tm->tm_sec = FIELD_GET(TOY_SEC, regs->reg0);
	tm->tm_min = FIELD_GET(TOY_MIN, regs->reg0);
	tm->tm_hour = FIELD_GET(TOY_HOUR, regs->reg0);
	tm->tm_mday = FIELD_GET(TOY_DAY, regs->reg0);
	tm->tm_mon = FIELD_GET(TOY_MON, regs->reg0) - 1;
}

static inline void ls2x_rtc_time_to_regs(struct rtc_time *tm,
					 struct ls2x_rtc_regs *regs)
{
	regs->reg0 = FIELD_PREP(TOY_SEC, tm->tm_sec);
	regs->reg0 |= FIELD_PREP(TOY_MIN, tm->tm_min);
	regs->reg0 |= FIELD_PREP(TOY_HOUR, tm->tm_hour);
	regs->reg0 |= FIELD_PREP(TOY_DAY, tm->tm_mday);
	regs->reg0 |= FIELD_PREP(TOY_MON, tm->tm_mon + 1);
	regs->reg1 = tm->tm_year;
}

static inline void ls2x_rtc_alarm_regs_to_time(struct ls2x_rtc_regs *regs,
					 struct rtc_time *tm)
{
	tm->tm_sec = FIELD_GET(TOY_MATCH_SEC, regs->reg0);
	tm->tm_min = FIELD_GET(TOY_MATCH_MIN, regs->reg0);
	tm->tm_hour = FIELD_GET(TOY_MATCH_HOUR, regs->reg0);
	tm->tm_mday = FIELD_GET(TOY_MATCH_DAY, regs->reg0);
	tm->tm_mon = FIELD_GET(TOY_MATCH_MON, regs->reg0) - 1;
	/*
	 * The rtc SYS_TOYMATCH0/YEAR bit field is only 6 bits,
	 * so it means 63 years at most. Therefore, The RTC alarm
	 * years can be set from 1900 to 1963.
	 * This causes the initialization of alarm fail during
	 * call __rtc_read_alarm. We add 64 years offset to
	 * ls2x_rtc_read_alarm. After adding the offset,
	 * the RTC alarm clock can be set from 1964 to 2027.
	 */
	tm->tm_year = FIELD_GET(TOY_MATCH_YEAR, regs->reg0) + 64;
}

static inline void ls2x_rtc_time_to_alarm_regs(struct rtc_time *tm,
					 struct ls2x_rtc_regs *regs)
{
	regs->reg0 = FIELD_PREP(TOY_MATCH_SEC, tm->tm_sec);
	regs->reg0 |= FIELD_PREP(TOY_MATCH_MIN, tm->tm_min);
	regs->reg0 |= FIELD_PREP(TOY_MATCH_HOUR, tm->tm_hour);
	regs->reg0 |= FIELD_PREP(TOY_MATCH_DAY, tm->tm_mday);
	regs->reg0 |= FIELD_PREP(TOY_MATCH_MON, tm->tm_mon + 1);
	regs->reg0 |= FIELD_PREP(TOY_MATCH_YEAR, tm->tm_year);
}

static int ls2x_rtc_read_time(struct device *dev, struct rtc_time *tm)
{
	int ret;
	struct ls2x_rtc_regs regs;
	struct ls2x_rtc_priv *priv = dev_get_drvdata(dev);

	ret = regmap_read(priv->regmap, TOY_READ1_REG, &regs.reg1);
	if (unlikely(ret))
		return ret;

	ret = regmap_read(priv->regmap, TOY_READ0_REG, &regs.reg0);
	if (unlikely(ret))
		return ret;

	ls2x_rtc_regs_to_time(&regs, tm);

	return 0;
}

static int ls2x_rtc_set_time(struct device *dev, struct rtc_time *tm)
{
	int ret;
	struct ls2x_rtc_regs regs;
	struct ls2x_rtc_priv *priv = dev_get_drvdata(dev);

	ls2x_rtc_time_to_regs(tm, &regs);

	ret = regmap_write(priv->regmap, TOY_WRITE0_REG, regs.reg0);
	if (unlikely(ret))
		return ret;

	return regmap_write(priv->regmap, TOY_WRITE1_REG, regs.reg1);
}

static int ls2x_rtc_read_alarm(struct device *dev, struct rtc_wkalrm *alrm)
{
	int ret;
	struct ls2x_rtc_regs regs;
	struct ls2x_rtc_priv *priv = dev_get_drvdata(dev);

	ret = regmap_read(priv->regmap, TOY_MATCH0_REG, &regs.reg0);
	if (unlikely(ret))
		return ret;

	ls2x_rtc_alarm_regs_to_time(&regs, &alrm->time);

#if defined(CONFIG_ACPI)
	ret = readl(priv->acpi_base + ACPI_PM1_EN_REG);
	alrm->enabled = !!(ret & RTC_EN);
#endif

	return 0;
}

static int ls2x_rtc_set_alarm(struct device *dev, struct rtc_wkalrm *alrm)
{
	struct ls2x_rtc_regs regs;
	struct ls2x_rtc_priv *priv = dev_get_drvdata(dev);

	ls2x_rtc_time_to_alarm_regs(&alrm->time, &regs);

	return regmap_write(priv->regmap, TOY_MATCH0_REG, regs.reg0);
}

static struct rtc_class_ops ls2x_rtc_ops = {
	.read_time = ls2x_rtc_read_time,
	.set_time = ls2x_rtc_set_time,
	.read_alarm = ls2x_rtc_read_alarm,
	.set_alarm = ls2x_rtc_set_alarm,
};

static int ls2x_rtc_probe(struct platform_device *pdev)
{
	int ret;
	void __iomem *regs;
	struct ls2x_rtc_priv *priv;
	struct device *dev = &pdev->dev;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (unlikely(!priv))
		return -ENOMEM;

	spin_lock_init(&priv->rtc_reglock);

	platform_set_drvdata(pdev, priv);

	regs = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(regs))
		return PTR_ERR(regs);

	priv->regmap = devm_regmap_init_mmio(dev, regs,
					     &ls2x_rtc_regmap_config);
	if (IS_ERR(priv->regmap))
		return PTR_ERR(priv->regmap);

	priv->rtcdev = devm_rtc_allocate_device(dev);
	if (IS_ERR(priv->rtcdev))
		return PTR_ERR(priv->rtcdev);

	/* Due to hardware erratum, all years multiple of 4 are considered
	 * leap year, so only years 2000 through 2099 are usable.
	 *
	 * Previous out-of-tree versions of this driver wrote tm_year directly
	 * into the year register, so epoch 2000 must be used to preserve
	 * semantics on shipped systems.
	 */
	priv->rtcdev->range_min = RTC_TIMESTAMP_BEGIN_2000;
	priv->rtcdev->range_max = RTC_TIMESTAMP_END_2099;
	priv->rtcdev->ops = &ls2x_rtc_ops;

#ifdef CONFIG_ACPI
	priv->acpi_base = regs - ACPI_RTC_OFFSET;
	acpi_install_fixed_event_handler(ACPI_EVENT_RTC,
					ls2x_acpi_fix_handler, priv);
#endif

	if (!device_can_wakeup(&pdev->dev))
		device_init_wakeup(dev, 1);

	ret = rtc_register_device(priv->rtcdev);
	if (unlikely(ret))
		return ret;

	/* An offset of -0.9s will call RTC set for wall clock time 10.0 s at 10.9 s */
	priv->rtcdev->set_offset_nsec = -900000000;

	/* If not cause hwclock huang */
	priv->rtcdev->uie_unsupported = 1;

	return ret;
}

#ifdef CONFIG_OF
static const struct of_device_id ls2x_rtc_of_match[] = {
	{ .compatible = "loongson,ls2x-rtc" },
	{ /* sentinel */ },
};
MODULE_DEVICE_TABLE(of, ls2x_rtc_of_match);
#endif

#ifdef CONFIG_ACPI
static const struct acpi_device_id ls2x_rtc_acpi_match[] = {
	{"LOON0001"},
	{}
};
MODULE_DEVICE_TABLE(acpi, ls2x_rtc_acpi_match);
#endif

static struct platform_driver ls2x_rtc_driver = {
	.probe		= ls2x_rtc_probe,
	.driver		= {
		.name	= "ls2x-rtc",
		.of_match_table = of_match_ptr(ls2x_rtc_of_match),
		.acpi_match_table = ACPI_PTR(ls2x_rtc_acpi_match),
	},
};

module_platform_driver(ls2x_rtc_driver);

MODULE_DESCRIPTION("LS2X RTC driver");
MODULE_AUTHOR("WANG Xuerui");
MODULE_AUTHOR("Huacai Chen");
MODULE_AUTHOR("Binbin Zhou");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:ls2x-rtc");
