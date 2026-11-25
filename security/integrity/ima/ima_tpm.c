// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Huawei Technologies Co., Ltd.
 *
 * Authors:
 * GONG Ruiqi <gongruiqi1@huawei.com>
 *
 * File: ima_rot_tpm.c
 *	TPM implementation of IMA RoT
 */

#include <linux/tpm.h>
#include <linux/module.h>

#include "ima.h"

static struct tpm_chip *ima_tpm_chip;

static void ima_pcrread(u32 idx, struct tpm_digest *d)
{
	if (!ima_tpm_chip)
		return;

	if (tpm_pcr_read(ima_tpm_chip, idx, d) != 0)
		pr_err("Error Communicating to TPM chip\n");
}

static int ima_pcr_extend(struct tpm_digest *digests_arg, int pcr)
{
	int result = 0;

	if (!ima_tpm_chip)
		return result;

	result = tpm_pcr_extend(ima_tpm_chip, pcr, digests_arg);
	if (result != 0)
		pr_err("Error Communicating to TPM chip, result: %d\n", result);
	return result;
}

int ima_tpm_init(struct ima_rot *rot)
{
	ima_tpm_chip = tpm_default_chip();
	if (!ima_tpm_chip)
		return -ENODEV;

	rot->nr_allocated_banks = ima_tpm_chip->nr_allocated_banks;
	rot->allocated_banks = ima_tpm_chip->allocated_banks;

	return 0;
}

int ima_tpm_extend(struct tpm_digest *digests_arg, const void *args)
{
	const int pcr = *(const int *)args;

	return ima_pcr_extend(digests_arg, pcr);
}

/*
 * The boot_aggregate is a cumulative hash over TPM registers 0 - 7.  With
 * TPM 1.2 the boot_aggregate was based on reading the SHA1 PCRs, but with
 * TPM 2.0 hash agility, TPM chips could support multiple TPM PCR banks,
 * allowing firmware to configure and enable different banks.
 *
 * Knowing which TPM bank is read to calculate the boot_aggregate digest
 * needs to be conveyed to a verifier.  For this reason, use the same
 * hash algorithm for reading the TPM PCRs as for calculating the boot
 * aggregate digest as stored in the measurement list.
 */
static int ima_calc_boot_aggregate_tfm(char *digest, u16 alg_id,
				       struct crypto_shash *tfm)
{
	struct tpm_digest d = { .alg_id = alg_id, .digest = {0} };
	int rc;
	u32 i;
	SHASH_DESC_ON_STACK(shash, tfm);

	shash->tfm = tfm;

	pr_devel("calculating the boot-aggregate based on TPM bank: %04x\n",
		 d.alg_id);

	rc = crypto_shash_init(shash);
	if (rc != 0)
		return rc;

	/* cumulative digest over TPM registers 0-7 */
	for (i = TPM_PCR0; i < TPM_PCR8; i++) {
		ima_pcrread(i, &d);
		/* now accumulate with current aggregate */
		rc = crypto_shash_update(shash, d.digest,
					 crypto_shash_digestsize(tfm));
		if (rc != 0)
			return rc;
	}
	/*
	 * Extend cumulative digest over TPM registers 8-9, which contain
	 * measurement for the kernel command line (reg. 8) and image (reg. 9)
	 * in a typical PCR allocation. Registers 8-9 are only included in
	 * non-SHA1 boot_aggregate digests to avoid ambiguity.
	 */
	if (alg_id != TPM_ALG_SHA1) {
		for (i = TPM_PCR8; i < TPM_PCR10; i++) {
			ima_pcrread(i, &d);
			rc = crypto_shash_update(shash, d.digest,
						crypto_shash_digestsize(tfm));
		}
	}
	if (!rc)
		rc = crypto_shash_final(shash, digest);
	return rc;
}

int ima_tpm_calc_boot_aggregate(struct ima_digest_data *hash)
{
	struct crypto_shash *tfm;
	u16 crypto_id, alg_id;
	int rc, i, bank_idx = -1;

	for (i = 0; i < NR_BANKS(ima_rot_inst); i++) {
		crypto_id = ima_rot_inst->allocated_banks[i].crypto_id;
		if (crypto_id == hash->algo) {
			bank_idx = i;
			break;
		}

		if (crypto_id == HASH_ALGO_SHA256)
			bank_idx = i;

		if (bank_idx == -1 && crypto_id == HASH_ALGO_SHA1)
			bank_idx = i;
	}

	if (bank_idx == -1) {
		pr_err("No suitable TPM algorithm for boot aggregate\n");
		return 0;
	}

	hash->algo = ima_rot_inst->allocated_banks[bank_idx].crypto_id;

	tfm = ima_alloc_tfm(hash->algo);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	hash->length = crypto_shash_digestsize(tfm);
	alg_id = ima_rot_inst->allocated_banks[bank_idx].alg_id;
	rc = ima_calc_boot_aggregate_tfm(hash->digest, alg_id, tfm);

	ima_free_tfm(tfm);

	return rc;
}
