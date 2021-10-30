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
#define HISI_TRNG_QUALITY	513

struct hisi_gm_trng {
	struct hwrng rng;
	void *va;
	phys_addr_t pa;
};

static int hisi_gm_trng_read(struct hwrng *rng, void *buf, size_t max, bool wait)
{
	struct arm_smccc_res res = {0};
	struct hisi_gm_trng *trng;
	int currsize = 0;

	trng = container_of(rng, struct hisi_gm_trng, rng);

	do {
		/* get gm true random number through bios */
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

static int hisi_gm_trng_probe(struct platform_device *pdev)
{
	struct hisi_gm_trng *trng;
	int ret;

	trng = devm_kzalloc(&pdev->dev, sizeof(*trng), GFP_KERNEL);
	if (!trng)
		return -ENOMEM;

	trng->rng.name = pdev->name;
	trng->rng.quality = HISI_TRNG_QUALITY;
	trng->rng.read = hisi_gm_trng_read;
	trng->va = devm_kzalloc(&pdev->dev, HISI_TRNG_SMC_BYTES, GFP_KERNEL);
	if (!trng->va)
		return -ENOMEM;

	trng->pa = virt_to_phys(trng->va);

	ret = devm_hwrng_register(&pdev->dev, &trng->rng);
	if (ret)
		dev_err(&pdev->dev, "failed to register hwrng!\n");

	return ret;
}

static const struct acpi_device_id hisi_gm_trng_acpi_tbl[] = {
	{ "HISI02B4", 0 },
	{ }
};
MODULE_DEVICE_TABLE(acpi, hisi_gm_trng_acpi_tbl);

static struct platform_driver hisi_gm_trng_driver = {
	.probe		= hisi_gm_trng_probe,
	.driver		= {
		.name	= "hisi-gm-trng",
		.acpi_match_table = ACPI_PTR(hisi_gm_trng_acpi_tbl),
	},
};

module_platform_driver(hisi_gm_trng_driver);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Yuan Wang <wangyuan46@huawei.com>");
MODULE_DESCRIPTION("HiSilicon GM auth true random number generator driver");

