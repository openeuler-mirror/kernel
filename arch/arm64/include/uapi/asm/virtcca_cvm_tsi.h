/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __ASM_VIRTCCA_CVM_TSI_H_
#define __ASM_VIRTCCA_CVM_TSI_H_

#include <linux/ioctl.h>

#define TSI_MAGIC 'T'

/* Measurement slot reserved for RIM */
#define RIM_MEASUREMENT_SLOT       (0U)

/* Maximum number of measurements */
#define MEASUREMENT_SLOT_NR        (5U)

/* Size in bytes of the SHA256 measurement */
#define SHA256_SIZE                (32U)

/* Size in bytes of the SHA512 measurement */
#define SHA512_SIZE                (64U)

/*
 * Size in bytes of the largest measurement type that can be supported.
 * This macro needs to be updated accordingly if new algorithms are supported.
 */
#define MAX_MEASUREMENT_SIZE       SHA512_SIZE
#define MAX_DEV_CERT_SIZE          (4096U)

#define GRANULE_SIZE               (4096U)
#define MAX_TOKEN_GRANULE_COUNT    (2U)
#define CHALLENGE_SIZE             (64U)

struct virtcca_cvm_measurement {
	int index;
	unsigned char value[MAX_MEASUREMENT_SIZE];
};

struct virtcca_cvm_tsi_version {
	int major;
	int minor;
};

struct virtcca_cvm_config {
	unsigned long ipa_bits; /* Width of IPA in bits */
	unsigned long algorithm;	/* Hash algorithm */
};

struct virtcca_cvm_measurement_extend {
	unsigned long index;
	unsigned long size;
	unsigned char value[MAX_MEASUREMENT_SIZE];
};

struct virtcca_cvm_attestation_cmd {
	unsigned char challenge[CHALLENGE_SIZE]; /* input: challenge value */
	unsigned char token[GRANULE_SIZE * MAX_TOKEN_GRANULE_COUNT];
	unsigned long token_size; /* return: token size */
};

struct virtcca_cvm_token_granule {
	void *head;
	void *ipa;  /* IPA of the Granule to which the token will be written */
	unsigned long count;
	unsigned long offset; /* Offset within Granule to start of buffer in bytes */
	unsigned long size;  /* Size of buffer in bytes */
	unsigned long num_wr_bytes; /* Number of bytes written to buffer */
};

struct virtcca_device_cert {
	unsigned long size;
	unsigned char value[MAX_DEV_CERT_SIZE];
};

#define TMM_GET_TSI_VERSION _IOR(TSI_MAGIC, 0, struct virtcca_cvm_tsi_version)

#define TMM_GET_ATTESTATION_TOKEN _IOWR(TSI_MAGIC, 1, struct virtcca_cvm_attestation_cmd)

#define TMM_GET_DEVICE_CERT _IOR(TSI_MAGIC, 2, struct virtcca_device_cert)

#endif  /* __ASM_VIRTCCA_CVM_TSI_H_ */
