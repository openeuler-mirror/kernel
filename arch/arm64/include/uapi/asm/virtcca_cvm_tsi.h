/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __ASM_VIRTCCA_CVM_TSI_H_
#define __ASM_VIRTCCA_CVM_TSI_H_

#include <linux/ioctl.h>
#include <linux/types.h>

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

#define MAX_BIND_VM                (256U)

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

struct pending_guest_rd_s {
	unsigned long long guest_rd[MAX_BIND_VM];
};

struct migration_info {
	unsigned char msk[32];
	unsigned char rand_iv[32];
	unsigned char tag[16];
	struct pending_guest_rd_s *pending_guest_rds;
	unsigned short slot_status;
	int is_src;
};

struct virtcca_migvm_info {
	enum ops {
		OP_MIGRATE_GET_ATTR = 0,
		OP_MIGRATE_SET_SLOT,
		OP_MIGRATE_PEEK_RDS
	} ops;
	/* if ops == OP_MIGRATE_GET_ATTR, the size is sizeof(content) */
	void *content;
	/* if ops == OP_MIGRATE_SET_SLOT, the size is sizeof(guest_rd) */
	unsigned long long guest_rd;
	unsigned long size;
};

#define TMM_GET_MIGRATION_INFO _IOWR(TSI_MAGIC, 3, struct virtcca_migvm_info)

struct virtcca_migvm_checksum_info {
	unsigned long guest_rd;
	unsigned long thread_id;
};

#define TMM_GET_MIGVM_MEM_CHECKSUM _IOW(TSI_MAGIC, 4, struct virtcca_migvm_checksum_info)

/*
 * Common data key structures and helper functions shared by TMI and TSI modules.
 */
#define DATA_KEY_MSK_LEN    32
#define DATA_KEY_IV_LEN     32
#define DATA_KEY_TAG_LEN    16
#define MAX_DATA_KEY_BUF_SIZE 4096 /* 4KB */

enum virtcca_enc_data_mode {
	DATA_ENC_MODE = 0,
	DATA_DEC_MODE = 1
};

struct virtcca_key_attr_s {
	__u8 msk_encrypted[DATA_KEY_MSK_LEN];
	__u8 rand_iv[DATA_KEY_IV_LEN];
	__u8 tag[DATA_KEY_TAG_LEN];
	__u64 data_rand_iv;
};

struct virtcca_raw_data_attr_s {
	__u64         data_rand_iv;
	__u64         ciphertext_p;
	__u32         ciphertext_len;
	__u64         plaintext_p;
	__u32         plaintext_len;
	__u8          tag[DATA_KEY_TAG_LEN];
	enum virtcca_enc_data_mode      mode;
};

struct virtcca_usr_data_key_enc_s {
	struct virtcca_key_attr_s    key_attr;
	struct virtcca_raw_data_attr_s      raw_data_attr;
};

struct virtcca_raw_data_kern_ctx {
	struct virtcca_key_attr_s *kern_key_attr;
	struct virtcca_raw_data_attr_s *kern_attr;
	void *ciphertext_buf;
	void *plaintext_buf;
	__u64 usr_ciphertext_p;
	__u64 usr_plaintext_p;
};

struct virtcca_tsi_data_key_attr {
	__u8 msk[DATA_KEY_MSK_LEN];
	__u8 rand_iv[DATA_KEY_IV_LEN];
	__u8 tag[DATA_KEY_TAG_LEN];
	__u64 data_rand_iv;
};

#define TMM_DATA_KEY_GEN _IOWR(TSI_MAGIC, 5, struct virtcca_tsi_data_key_attr)

#define TMM_DATA_KEY_ENC _IOWR(TSI_MAGIC, 6, struct virtcca_usr_data_key_enc_s)

#endif  /* __ASM_VIRTCCA_CVM_TSI_H_ */
