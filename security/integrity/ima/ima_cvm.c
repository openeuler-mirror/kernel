// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024. Huawei Technologies Co., Ltd. All rights reserved.
 */
#include <asm/cvm_smc.h>
#include "ima_cvm.h"

static bool ima_tsi_cvm;

bool ima_cvm_available(void)
{
	return ima_tsi_cvm;
}

int __init ima_cvm_init(void)
{
	int rc = -ENODEV;

	if (tsi_get_version() != SMCCC_RET_NOT_SUPPORTED) {
		ima_tsi_cvm = true;
		rc = 0;
	}

	return rc;
}

int ima_calc_cvm_boot_aggregate(struct ima_digest_data *hash)
{
	unsigned long result;
	int hash_len;
	struct cvm_config cfg = { 0 };
	struct cvm_measurement cm = { 0 };

	result = tsi_get_cvm_config(&cfg);
	if (result != TSI_SUCCESS) {
		pr_err("Error reading cvm config for boot aggregate\n");
		return -EFAULT;
	}

	/* 0: SHA256, 1: SHA512 */
	hash->algo = cfg.algorithm ? HASH_ALGO_SHA512 : HASH_ALGO_SHA256;
	hash_len = hash_digest_size[hash->algo];

	/* Read the measurement result of RIM as the boot aggregate */
	cm.index = RIM_MEASUREMENT_SLOT;

	result = tsi_measurement_read(&cm);
	if (result != TSI_SUCCESS) {
		pr_err("Error reading cvm measurement 0 for boot aggregate\n");
		return -EFAULT;
	}

	memcpy(hash->digest, cm.value, hash_len);

	return 0;
}

int ima_cvm_extend(struct tpm_digest *digests_arg)
{
	struct cvm_measurement_extend cme;

	if (!ima_tsi_cvm)
		return 0;

	/* Use index 1 as CVM IMA slot */
	cme.index = 1;
	cme.size = hash_digest_size[ima_hash_algo];
	memcpy(cme.value, digests_arg[ima_hash_algo_idx].digest, cme.size);

	return tsi_measurement_extend(&cme) == TSI_SUCCESS ? 0 : -EFAULT;
}
