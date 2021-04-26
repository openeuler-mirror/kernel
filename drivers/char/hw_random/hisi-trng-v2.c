// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 HiSilicon Limited. */

#include <linux/acpi.h>
#include <linux/err.h>
#include <linux/hw_random.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/random.h>
#include <linux/arm-smccc.h>

#define HISI_TRNG_SMC_CMD	0x83000109
#define HISI_TRNG_SMC_BYTES	32
#define HISI_TRNG_REG		0x00F0
#define HISI_TRNG_BYTES		4
#define HISI_TRNG_QUALITY	512
#define SLEEP_US		10
#define TIMEOUT_US		10000
#define RAND_DATA_NORMAL	0
#define RAND_DATA_POSTPRO	1

struct hisi_trng {
	void __iomem *base;
	struct hwrng rng;
	void *va;
	phys_addr_t pa;
};

static int data_mode_set(const char *val, const struct kernel_param *kp)
{
	u32 n;
	int ret;

	if (!val)
		return -EINVAL;

	ret = kstrtou32(val, 10, &n);
	if (ret < 0 || (n != RAND_DATA_NORMAL && n != RAND_DATA_POSTPRO))
		return -EINVAL;

	return param_set_int(val, kp);
}

static const struct kernel_param_ops data_mode_ops = {
	.set = data_mode_set,
	.get = param_get_int,
};

static int data_mode = RAND_DATA_NORMAL;
module_param_cb(data_mode, &data_mode_ops, &data_mode, 0444);
MODULE_PARM_DESC(data_mode, "Rand data with post process or not, 0(default), 1");

static int hisi_trng_read_v2(struct hwrng *rng, void *buf, size_t max,
				   bool wait)
{
	struct arm_smccc_res res = {0};
	struct hisi_trng *trng;
	int currsize = 0;

	trng = container_of(rng, struct hisi_trng, rng);

	do {
		arm_smccc_smc(HISI_TRNG_SMC_CMD, trng->pa, 0, 0, 0, 0, 0, 0,
			      &res);
		if (res.a0)
			return currsize;

		if (max - currsize >= HISI_TRNG_SMC_BYTES) {
			memcpy(buf + currsize, trng->va, HISI_TRNG_SMC_BYTES);
			currsize += HISI_TRNG_SMC_BYTES;
			if (currsize == max)
				return currsize;
			continue;
		}

		memcpy(buf + currsize, trng->va, max - currsize);
		currsize = max;
	} while (currsize < max);

	return currsize;
}

static int hisi_trng_read(struct hwrng *rng, void *buf, size_t max, bool wait)
{
	struct hisi_trng *trng;
	int currsize = 0;
	u32 val = 0;
	u32 ret;

	trng = container_of(rng, struct hisi_trng, rng);

	do {
		ret = readl_poll_timeout(trng->base + HISI_TRNG_REG, val,
					 val, SLEEP_US, TIMEOUT_US);
		if (ret)
			return currsize;

		if (max - currsize >= HISI_TRNG_BYTES) {
			memcpy(buf + currsize, &val, HISI_TRNG_BYTES);
			currsize += HISI_TRNG_BYTES;
			if (currsize == max)
				return currsize;
			continue;
		}

		/* copy remaining bytes */
		memcpy(buf + currsize, &val, max - currsize);
		currsize = max;
	} while (currsize < max);

	return currsize;
}

static int hisi_trng_probe(struct platform_device *pdev)
{
	struct hisi_trng *trng;
	struct resource *res;
	int ret;

	trng = devm_kzalloc(&pdev->dev, sizeof(*trng), GFP_KERNEL);
	if (!trng)
		return -ENOMEM;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	trng->base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(trng->base))
		return PTR_ERR(trng->base);

	trng->rng.name = pdev->name;
	trng->rng.quality = HISI_TRNG_QUALITY;

	if (data_mode) {
		trng->rng.read = hisi_trng_read_v2;
		trng->va = devm_kzalloc(&pdev->dev, HISI_TRNG_SMC_BYTES,
					GFP_KERNEL);
		if (!trng->va)
			return -ENOMEM;

		trng->pa = virt_to_phys(trng->va);
	} else
		trng->rng.read = hisi_trng_read;

	ret = devm_hwrng_register(&pdev->dev, &trng->rng);
	if (ret)
		dev_err(&pdev->dev, "failed to register hwrng!\n");

	return ret;
}

static const struct acpi_device_id hisi_trng_acpi_match[] = {
	{ "HISI02B3", 0 },
	{ }
};
MODULE_DEVICE_TABLE(acpi, hisi_trng_acpi_match);

static struct platform_driver hisi_trng_driver = {
	.probe		= hisi_trng_probe,
	.driver		= {
		.name	= "hisi-trng-v2",
		.acpi_match_table = ACPI_PTR(hisi_trng_acpi_match),
	},
};

module_platform_driver(hisi_trng_driver);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Yuan Wang <wangyuan46@huawei.com>");
MODULE_AUTHOR("Weili Qian <qianweili@huawei.com>");
MODULE_AUTHOR("Zaibo Xu <xuzaibo@huawei.com>");
MODULE_DESCRIPTION("HiSilicon true random number generator V2 driver");
