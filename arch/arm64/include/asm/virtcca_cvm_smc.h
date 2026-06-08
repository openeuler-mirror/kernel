/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_VIRTCCA_CVM_SMC_H_
#define __ASM_VIRTCCA_CVM_SMC_H_

#ifdef CONFIG_HISI_VIRTCCA_GUEST

#include <linux/arm-smccc.h>
#include <asm/virtcca_cvm_tsi.h>
#include <linux/slab.h>

#define SMC_TSI_CALL_BASE           0xC4000000
#define TSI_ABI_VERSION_MAJOR       1
#define TSI_ABI_VERSION_MINOR       0
#define TSI_ABI_VERSION             ((TSI_ABI_VERSION_MAJOR << 16) | TSI_ABI_VERSION_MINOR)

#define TSI_ABI_VERSION_GET_MAJOR(_version) ((_version) >> 16)
#define TSI_ABI_VERSION_GET_MINOR(_version) ((_version) & 0xFFFF)

#define TSI_SUCCESS             0
#define TSI_ERROR_INPUT         1
#define TSI_ERROR_STATE         2
#define TSI_INCOMPLETE          3

#define SMC_TSI_FID(_x)                        (SMC_TSI_CALL_BASE + (_x))
#define SMC_TSI_ABI_VERSION                    SMC_TSI_FID(0x190)

/*
 * arg1: Index, which measurements slot to read
 * arg2: Measurement value
 * ret0: Status / error
 */
#define SMC_TSI_MEASUREMENT_READ            SMC_TSI_FID(0x192)

/*
 * arg1: Index, which measurements slot to extend
 * arg2: Size of realm measurement in bytes, max 64 bytes
 * arg3: Measurement value
 * ret0: Status / error
 */
#define SMC_TSI_MEASUREMENT_EXTEND          SMC_TSI_FID(0x193)

/*
 * arg1: Challenge value
 * ret0: Status / error
 * ret1: Upper bound on attestation token size in bytes
 */
#define SMC_TSI_ATTESTATION_TOKEN_INIT      SMC_TSI_FID(0x194)

/*
 * arg1: IPA of the Granule to which the token will be written
 * arg2: Offset within Granule to start of buffer in bytes
 * arg3: Size of buffer in bytes
 * ret0: Status / error
 * ret1: Number of bytes written to buffer
 */
#define SMC_TSI_ATTESTATION_TOKEN_CONTINUE  SMC_TSI_FID(0x195)

/*
 * arg1: struct cVM config addr
 * ret0: Status / error
 */
#define SMC_TSI_CVM_CONFIG				    SMC_TSI_FID(0x196)

/*
 * arg1: Device cert buffer
 * arg2: Size of buffer in bytes
 * ret0: Status / error
 */
#define SMC_TSI_DEVICE_CERT                 SMC_TSI_FID(0x19A)

/*
 * arg0: Paddr of rd
 * arg1: Paddr of memory to unmap
 * arg2: Size of memory to unmap
 */
#define SMC_TSI_SEC_MEM_UNMAP              SMC_TSI_FID(0x19C)

/*
 * arg1: Paddr of might binded guest_rd
 * arg2: Paddr of structure to get attr
 * arg3: Size of structure to get attr
 * ret0: Status / error
 */
#define SMC_TSI_MIGVM_GET_ATTR				SMC_TSI_FID(0x19D)

/*
 * arg1: Paddr of might binded guest_rd
 * arg2: Paddr of structure to get attr
 * arg3: Size of structure to get attr
 * ret0: Status / error
 */
#define SMC_TSI_MIGVM_SET_SLOT				SMC_TSI_FID(0x19E)

/*
 * arg1: Paddr of might binded guest_rd
 * arg2: Paddr of structure to get attr
 * arg3: Size of structure to get attr
 * ret0: Status / error
 */
#define SMC_TSI_MIGVM_PEEK_BINDINGRD		SMC_TSI_FID(0x19F)

/*
 * arg1: Paddr of dest rd
 * arg2: Paddr of queue
 */
#define SMC_TSI_MIG_INTEGRITY_CHECKSUM_INIT	SMC_TSI_FID(0x1A0)

/*
 * arg1: Paddr of dest rd
 */
#define SMC_TSI_MIG_INTEGRITY_CHECKSUM_LOOP	SMC_TSI_FID(0x1A1)

/*
 * arg1: Paddr of data key attr structure
 * ret0: Status / error
 */
#define SMC_TSI_DATA_KEY_GEN			SMC_TSI_FID(0x1A2)

/*
 * arg1: Paddr of key attr structure
 * arg2: Paddr of raw data attr structure
 * ret0: Status / error
 */
#define SMC_TSI_DATA_KEY_ENC			SMC_TSI_FID(0x1A3)


static inline unsigned long tsi_get_version(void)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(SMC_TSI_ABI_VERSION, &res);

	return res.a0;
}

static inline unsigned long tsi_get_cvm_config(struct virtcca_cvm_config *cfg)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(SMC_TSI_CVM_CONFIG, &res);

	cfg->ipa_bits = res.a1;
	cfg->algorithm = res.a2;

	return res.a0;
}

static inline unsigned long tsi_measurement_extend(struct virtcca_cvm_measurement_extend *cvm_meas_ext)
{

	struct arm_smccc_res res;
	unsigned char *value;

	value = kmalloc(MAX_MEASUREMENT_SIZE, GFP_KERNEL);
	if (!value)
		return -ENOMEM;
	memcpy(value, cvm_meas_ext->value, MAX_MEASUREMENT_SIZE);

	arm_smccc_1_1_smc(SMC_TSI_MEASUREMENT_EXTEND, cvm_meas_ext->index,
		cvm_meas_ext->size, virt_to_phys(value), &res);
	kfree(value);

	return res.a0;
}

static inline unsigned long tsi_measurement_read(struct virtcca_cvm_measurement *cvm_meas)
{
	struct arm_smccc_res res;
	unsigned char *value;

	value = kmalloc(MAX_MEASUREMENT_SIZE, GFP_KERNEL);
	if (!value)
		return -ENOMEM;
	arm_smccc_1_1_smc(SMC_TSI_MEASUREMENT_READ, cvm_meas->index,
		virt_to_phys(value), &res);

	memcpy(cvm_meas->value, value, MAX_MEASUREMENT_SIZE);
	kfree(value);

	return res.a0;
}

static inline unsigned long tsi_attestation_token_init(unsigned char *challenge)
{
	struct arm_smccc_res res;
	unsigned char *buf;

	buf = kmalloc(CHALLENGE_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	memcpy(buf, challenge, CHALLENGE_SIZE);

	arm_smccc_1_1_smc(SMC_TSI_ATTESTATION_TOKEN_INIT, virt_to_phys(buf), &res);
	kfree(buf);

	return res.a0;
}

static inline unsigned long tsi_attestation_token_continue(struct virtcca_cvm_token_granule *token_granule)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(SMC_TSI_ATTESTATION_TOKEN_CONTINUE, virt_to_phys(token_granule->ipa),
		token_granule->offset, token_granule->size, &res);

	token_granule->num_wr_bytes = res.a1;

	return res.a0;
}

static inline unsigned long tsi_get_device_cert(unsigned char *device_cert,
	unsigned long *device_cert_size)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(SMC_TSI_DEVICE_CERT, virt_to_phys(device_cert), *device_cert_size, &res);

	*device_cert_size = res.a1;

	return res.a0;
}

static inline unsigned long tsi_peek_binding_list(void *user_buf)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(SMC_TSI_MIGVM_PEEK_BINDINGRD, virt_to_phys(user_buf), &res);

	return res.a0;
}

static inline unsigned long tsi_migvm_get_attr(unsigned long guest_rd, void *user_buf)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(SMC_TSI_MIGVM_GET_ATTR, guest_rd, virt_to_phys(user_buf), &res);

	return res.a0;
}

static inline unsigned long tsi_migvm_set_slot(unsigned long guest_rd, void *user_buf)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(SMC_TSI_MIGVM_SET_SLOT, guest_rd, virt_to_phys(user_buf), &res);

	return res.a0;
}

static inline unsigned long tsi_mig_integrity_checksum_init(unsigned long dst_rd,
	unsigned long queue_pa)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(SMC_TSI_MIG_INTEGRITY_CHECKSUM_INIT, dst_rd, queue_pa, &res);

	return res.a0;
}

static inline unsigned long tsi_mig_integrity_checksum_loop(unsigned long guest_rd,
	unsigned long thread_id)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(SMC_TSI_MIG_INTEGRITY_CHECKSUM_LOOP, guest_rd, thread_id, &res);

	return res.a0;
}

static inline unsigned long tsi_data_key_gen(void *data_key_attr)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(SMC_TSI_DATA_KEY_GEN, virt_to_phys(data_key_attr), &res);

	return res.a0;
}

static inline unsigned long tsi_data_key_enc(void *key_attr, void *raw_data_attr)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(SMC_TSI_DATA_KEY_ENC, virt_to_phys(key_attr),
		virt_to_phys(raw_data_attr), &res);

	return res.a0;
}

#endif /* CONFIG_HISI_VIRTCCA_GUEST */
#endif  /* __ASM_VIRTCCA_CVM_SMC_H_ */
