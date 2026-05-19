/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2024, The Linux Foundation. All rights reserved.
 */
#ifndef __ASM_KVM_TMM_H
#define __ASM_KVM_TMM_H

#include <uapi/linux/kvm.h>
#include <asm/rmi_smc.h>
enum virtcca_cvm_state {
	CVM_STATE_NONE = 1,
	CVM_STATE_NEW,
	CVM_STATE_ACTIVE,
	CVM_STATE_DYING
};

#define VIRTCCA_MIG_DST		0
#define VIRTCCA_MIG_SRC		1

#define MAX_KAE_VF_NUM	11

/*
 * Many of these fields are smaller than u64 but all fields have u64
 * alignment, so use u64 to ensure correct alignment.
 */
struct tmi_cvm_params {
	u64	flags;
	u64	s2sz;
	u64	sve_vl;
	u64	num_bps;
	u64	num_wps;
	u64	pmu_num_cnts;
	u64	measurement_algo;
	u64	vmid;
	u64	ns_vtcr;
	u64	vttbr_el2;
	u64	ttt_base;
	s64	ttt_level_start;
	u64	ttt_num_start;
	u8	rpv[64]; /* Bits 512 */
	u64	kae_vf_num;
	u64	sec_addr[MAX_KAE_VF_NUM];
	u64	hpre_addr[MAX_KAE_VF_NUM];
#ifndef __GENKSYMS__
	u32 mig_enable; /* check the base capability of CVM migration */
	u32 mig_src; /* check the CVM is source or dest*/
	u32 migration_migvm_cap; /* the type of CVM (support migration) */
#endif
};

#define CVM_NAME_LEN 64
#define CVM_MIG_IP_LEN 16
#define CVM_MIG_SYNC_NUM_MAX 1

/* the guest cvm and migcvm both use this structure */
#define KVM_CVM_MIGVM_VERSION 0
struct mig_cvm {
	/* used by guest cvm */
	uint64_t migvm_cid; /* vsock cid of migvm */
	uint8_t  version; /* kvm version of migcvm*/
	uint16_t dst_port;  /* port of destination cvm */
	char     dst_ip[CVM_MIG_IP_LEN];    /* ip of destination cvm */
	uint8_t  is_migcvm; /* indicates whether the device is a migcvm. */
	char     reserved;
};

#define TMI_MAGIC 'T'
#define VIRTCCA_TMI_IOCTL_ENTER _IOWR(TMI_MAGIC, 0x1, struct virtcca_tmi_cmd)
/* virtcca tmi sub-ioctl() commands. */
enum virtcca_tmi_cmd_id {
	VIRTCCA_TMI_IOCTL_VERSION = 0,
	VIRTCCA_TMI_GET_NOTIFY,
	VIRTCCA_GET_MIGVM_MEM_CHECKSUM,
	VIRTCCA_GET_DSTVM_RD,
	VIRTCCA_GET_MIG_KEY,
	VIRTCCA_SET_MIG_KEY,

	VIRTCCA_TMI_IOCTL_CMD_MAX,
};

struct cvm {
	enum virtcca_cvm_state state;
	u32 cvm_vmid;
	u64 rd;
	u64 loader_start;
	u64 initrd_start;
	u64 initrd_size;
	u64 ram_size;
	struct kvm_numa_info numa_info;
	struct tmi_cvm_params *params;
	bool is_cvm;
};

struct virtcca_cvm {
	enum virtcca_cvm_state state;
	u32 cvm_vmid;
	u64 rd;
	u64 loader_start;
#ifndef __GENKSYMS__
	union {
		u64 image_end;
		u64 mmio_start;
	};
	union {
		u64 initrd_start;
		u64 mmio_end;
	};
#else
	u64 image_end;
	u64 initrd_start;
#endif
	u64 dtb_end;
	u64 ram_size;
	struct kvm_numa_info numa_info;
	struct tmi_cvm_params *params;
	bool is_mapped; /* Whether the cvm RAM memory is mapped */
#ifndef __GENKSYMS__
	struct virtcca_mig_state *mig_state;
	struct mig_cvm *mig_cvm_info;
	u64 swiotlb_start;
	u64 swiotlb_end;
	u64 ipa_start;
#endif
};

/*
 * struct cvm_tec - Additional per VCPU data for a CVM
 */
struct virtcca_cvm_tec {
	u64 tec;
	bool tec_created;
	KABI_REPLACE(void *tec_run, struct tmi_tec_run *run)
};

#ifdef CONFIG_HISI_VIRTCCA_HOST
/*
 * There is a conflict with the internal iova of CVM,
 * so it is necessary to offset the msi iova.
 * According to qemu file(hw/arm/virt.c), 0x0a001000 - 0x0b000000
 * iova is not being used, so it is used as the iova range for msi
 * mapping.
 */
#define CVM_MSI_ORIG_IOVA      0x8000000
#define CVM_MSI_MIN_IOVA       0x0a001000
#define CVM_MSI_MAX_IOVA       0x0b000000
#define CVM_MSI_IOVA_OFFSET    0x1000

#define CVM_RW_8_BIT	0x8
#define CVM_RW_16_BIT	0x10
#define CVM_RW_32_BIT	0x20
#define CVM_RW_64_BIT	0x40

struct virtcca_tmi_cmd {
	__u32 id;
	__u32 flags;
	__u64 data;
	__u64 ret_val;
};

/* Mark verifier status to indicate mig agent to update migration info */
enum virtcca_mig_verifier_status {
	VIRTCCA_MIG_NEW = 0,
	VIRTCCA_MIG_UPDATED,
	VIRTCCA_MIG_NOTIFIED,
	VIRTCCA_MIG_KEY_UPDATED,

	VIRTCCA_MIG_STATUS_MAX,
};

/* info to agent */
struct virtcca_mig_agent_notify_info {
	char		name[CVM_NAME_LEN];
	char		dst_ip[CVM_MIG_IP_LEN];
	uint64_t	rd;
	uint16_t	dst_port;
	uint16_t	cvm_vmid;
	uint16_t	is_src;
};

struct virtcca_mig_verifier {
	char		name[CVM_NAME_LEN];
	char		dst_ip[CVM_MIG_IP_LEN];
	uint64_t	rd;
	uint16_t	dst_port;
	uint16_t	cvm_vmid;
	uint16_t	is_src;
	wait_queue_head_t wait_queue;
	atomic_t	status;
	struct list_head list;
};

/* info from qemu */
struct virtcca_mig_dst_host_info {
	char      name[CVM_NAME_LEN];
	char      dst_ip[CVM_MIG_IP_LEN];
	uint16_t  dst_port;
	uint8_t   is_src;
	uint8_t   migcvm_enabled;
	uint8_t   version;
};

struct mig_host_key_info {
	uint8_t msk[32];
	uint8_t rand_iv[32];
	uint8_t tag[16];
};

/* used for mig agent forwarding data between the secure and non-secure worlds. */
struct virtcca_mig_host_agent_info {
	uint64_t      rd;
	void          *content;
	unsigned long size;
};

struct cvm_ttt_addr {
	struct list_head list;
	u64 addr;
};

void kvm_init_tmm(void);
int kvm_cvm_enable_cap(struct kvm *kvm, struct kvm_enable_cap *cap);
void kvm_destroy_cvm(struct kvm *kvm);
int kvm_finalize_vcpu_tec(struct kvm_vcpu *vcpu);
void kvm_destroy_tec(struct kvm_vcpu *vcpu);
int kvm_tec_enter(struct kvm_vcpu *vcpu);
int handle_cvm_exit(struct kvm_vcpu *vcpu, int rec_run_status);
int kvm_arm_create_cvm(struct kvm *kvm);
void kvm_free_rd(struct kvm *kvm);
int cvm_psci_complete(struct kvm_vcpu *calling, struct kvm_vcpu *target, unsigned long status);

void kvm_cvm_unmap_destroy_range(struct kvm *kvm);
int kvm_cvm_map_range(struct kvm *kvm);
int virtcca_cvm_arm_smmu_domain_set_kvm(void *group);
int cvm_map_unmap_ipa_range(struct kvm *kvm, phys_addr_t ipa_base, phys_addr_t pa,
	unsigned long map_size, uint32_t is_map);
int kvm_cvm_map_ipa_mmio(struct kvm *kvm, phys_addr_t ipa_base,
	phys_addr_t pa, unsigned long map_size);

bool is_in_virtcca_ram_range(struct kvm *kvm, uint64_t iova);
bool is_virtcca_iova_need_vfio_dma(struct kvm *kvm, uint64_t iova);

#define CVM_TTT_BLOCK_LEVEL	2
#define CVM_TTT_MAX_LEVEL	3

#define CVM_MAP_IPA_RAM	1
#define CVM_MAP_IPA_SMMU	2
#define CVM_MAP_IPA_UNPROTECTED	4

#define CVM_PAGE_SHIFT		12
#define CVM_PAGE_SIZE		BIT(CVM_PAGE_SHIFT)
#define CVM_TTT_LEVEL_SHIFT(l)	\
	((CVM_PAGE_SHIFT - 3) * (4 - (l)) + 3)
#define CVM_L2_BLOCK_SIZE	BIT(CVM_TTT_LEVEL_SHIFT(2))

#define TMM_GRANULE_SIZE2		12
#define TMM_TTT_WIDTH			9
#define TMM_GRANULE_SIZE		(1UL << TMM_GRANULE_SIZE2)
#define tmm_granule_size(level)	(TMM_GRANULE_SIZE << ((3 - level)) * TMM_TTT_WIDTH)

static inline unsigned long cvm_ttt_level_mapsize(int level)
{
	if (WARN_ON(level > CVM_TTT_BLOCK_LEVEL))
		return CVM_PAGE_SIZE;

	return (1UL << CVM_TTT_LEVEL_SHIFT(level));
}

/* virtcca MIG sub-ioctl() commands. */
enum kvm_cvm_cmd_id {
	/*  virtcca MIG migcvm commands. */
	KVM_CVM_MIGCVM_SET_CID = 0,
	KVM_CVM_MIG_NOTIFY,
	KVM_CVM_GET_BIND_STATUS,
	KVM_CVM_MIG_EXPORT_ABORT,
	/* virtcca MIG stream commands. */
	KVM_CVM_MIG_STREAM_START,
	KVM_CVM_MIG_EXPORT_STATE_IMMUTABLE,
	KVM_CVM_MIG_IMPORT_STATE_IMMUTABLE,
	KVM_CVM_MIG_EXPORT_MEM,
	KVM_CVM_MIG_IMPORT_MEM,
	KVM_CVM_MIG_EXPORT_TRACK,
	KVM_CVM_MIG_IMPORT_TRACK,
	KVM_CVM_MIG_EXPORT_PAUSE,
	KVM_CVM_MIG_EXPORT_STATE_TEC,
	KVM_CVM_MIG_IMPORT_STATE_TEC,
	KVM_CVM_MIG_IMPORT_END,
	KVM_CVM_MIG_CRC,
	KVM_CVM_MIG_GET_MIG_INFO,
	KVM_CVM_MIG_IS_ZERO_PAGE,
	KVM_CVM_MIG_IMPORT_ZERO_PAGE,

	KVM_CVM_MIG_CMD_NR_MAX,
};

struct kvm_virtcca_mig_cmd {
	/* enum kvm_virtcca_cmd_id */
	__u32 id;
	/* flags for sub-commend. If sub-command doesn't use this, set zero. */
	__u32 flags;
	/*
	 * data for each sub-command. An immediate or a pointer to the actual
	 * data in process virtual address.  If sub-command doesn't use it,
	 * set zero.
	 */
	__u64 data;
	/*
	 * Auxiliary error code.  The sub-command may return virtCCA SEAMCALL
	 * status code in addition to -Exxx.
	 * Defined for consistency with struct kvm_sev_cmd.
	 */
	__u64 error;
};

/* mig virtcca head*/
#define KVM_DEV_VIRTCCA_MIG_ATTR	0x1

struct kvm_dev_virtcca_mig_attr {
#define KVM_DEV_VIRTCCA_MIG_ATTR_VERSION	0
	__u32 version;
/* 4KB buffer can hold 512 entries at most */
#define VIRTCCA_MIG_BUF_LIST_PAGES_MAX		512
	__u32 buf_list_pages;
	__u32 max_migs;
};

#define VIRTCCA_MIG_STREAM_MBMD_MAP_OFFSET		0
#define VIRTCCA_MIG_STREAM_GPA_LIST_MAP_OFFSET	1
#define VIRTCCA_MIG_STREAM_MAC_LIST_MAP_OFFSET	2
#define VIRTCCA_MIG_STREAM_BUF_LIST_MAP_OFFSET	4

struct virtcca_bind_info {
	int16_t version;
	bool premig_done;
};

struct virtcca_mig_mbmd_data {  /* both kvm and tmm can access */
	__u16 size;
	__u16 mig_version;
	__u16 migs_index; /* corresponding stream idx */
	__u8  mb_type;
	__u8  rsvd0; /* reserve bit */
	__u32 mb_counter;
	__u32 mig_epoch;
	__u64 iv_counter;
	__u8  type_specific_info[];
} __packed;

struct virtcca_mig_mbmd {
	struct virtcca_mig_mbmd_data *data;
	uint64_t hpa_and_size; /* Host physical address and size of the mbmd */
};

#define VIRTCCA_MIG_EPOCH_START_TOKEN 0xffffffff

union virtcca_mig_buf_list_entry {
	uint64_t val;
	struct {
		uint64_t rsvd0		: 12;
		uint64_t pfn		: 40;
		uint64_t rsvd1		: 11;
		uint64_t invalid	: 1;
	};
};

struct virtcca_mig_buf_list {
	union virtcca_mig_buf_list_entry *entries;
	hpa_t hpa;
};

union virtcca_mig_page_list_info {
	uint64_t val;
	struct {
		uint64_t rsvd0		: 12;
		uint64_t pfn		: 40;
		uint64_t rsvd1		: 3;
		uint64_t last_entry	: 9;
	};
};

struct virtcca_mig_page_list {
	hpa_t *entries;
	union virtcca_mig_page_list_info info;
};

union virtcca_mig_gpa_list_entry {
	uint64_t val;
	struct{
		uint64_t level		: 2;	/* Bits 1:0: Mapping level */
		uint64_t pending	: 1;	/* Bit 2: Page is pending */
		uint64_t reserved_0	: 4;	/* Bits 6:3 */
		uint64_t l2_map		: 3;	/* Bits 9:7: L2 mapping flags */
		uint64_t mig_type	: 2;	/* Bits 11:10: Migration type */
		uint64_t gfn		: 40;	/* Bits 51:12 */
#define GPA_LIST_OP_NOP		0
#define GPA_LIST_OP_EXPORT	1
#define GPA_LIST_OP_CANCEL	2
		uint64_t operation	: 2;	/* Bits 53:52 */
		uint64_t reserved_1	: 2;	/* Bits 55:54 */
#define GPA_LIST_S_SUCCESS	0
		uint64_t status		: 5;	/* Bits 56:52 */
		uint64_t reserved_2	: 3;	/* Bits 63:61 */
	};
};

#define TMM_MAX_DIRTY_BITMAP_LEN 8

union virtcca_mig_ipa_list_info {
	uint64_t val;
	struct {
		uint64_t rsvd0		: 3;
		uint64_t first_entry: 9;
		uint64_t pfn		: 40;
		uint64_t rsvd1		: 3;
		uint64_t last_entry	: 9;
	};
};

struct virtcca_mig_gpa_list {
	union virtcca_mig_gpa_list_entry *entries;
	union virtcca_mig_ipa_list_info info;
};

struct virtcca_mig_mac_list {
	void *entries;
	hpa_t hpa;
};

union virtcca_mig_stream_info {
	uint64_t val;
	struct {
		uint64_t index	: 16;
		uint64_t rsvd	: 47;
		uint64_t resume	: 1;
	};
	struct {
		uint64_t rsvd1	  : 63;
		uint64_t in_order : 1;
	};
};

struct virtcca_mig_stream {
	uint16_t idx; /* stream id */
	uint32_t buf_list_pages;  /* ns memory page number of buf_list 5<n<512 */

	struct virtcca_mig_mbmd mbmd;   /* ns memory */
	/* for export status and mem*/
	/* List of buffers to export/import the private memory data */
	struct virtcca_mig_buf_list mem_buf_list;
	/* List of buffers to export/miport the non-memory state data */
	struct virtcca_mig_page_list page_list;
	/* List of GPA entries used when export/import private memory */
	struct virtcca_mig_gpa_list gpa_list;
	/* List of MACs used when export/import private memory */
	struct virtcca_mig_mac_list mac_list[2];
	/* List of dest private pages */
	struct virtcca_mig_buf_list dst_buf_list;
	/*
	 * List of buffers grabbed either from the private_fd allocated pages
	 * for in-place import or from mem_buf_list for non-in-place import.
	 */
	struct virtcca_mig_buf_list import_mem_buf_list;
	/*
	 * Bitmap to get if a gpa in the gpa_list to import needs first-time
	 * import, i.e. the leaf entry has not been set up in sept tables.
	 * Support up to 512 pages in a batch.
	 */
	uint64_t first_time_import_bitmap[8];
};

struct virtcca_mig_state {
	/* Number of streams created */
	atomic_t streams_created;
	hpa_t *migsc_paddrs;
	struct virtcca_mig_gpa_list blockw_gpa_list;
	struct virtcca_mig_stream *default_stream;
	/* Backward stream used on migration abort during post-copy */
	struct virtcca_mig_stream backward_stream;
	hpa_t backward_migsc_paddr;
	bool bugged;
	/* Index of the next vCPU to export the state */
	uint32_t vcpu_export_next_idx;
	uint32_t mig_src;
};

struct virtcca_mig_capabilities {
	uint32_t max_migs;
	uint32_t nonmem_state_pages;
};

struct migcvm_agent_listen_cids {
	uint64_t cid;
};

struct tmi_mig_mem_data {
	uint64_t	gpa_list_info;
	uint64_t	mig_buff_list_pa;
	uint64_t	mig_cmd;
	uint64_t	mbmd_hpa_and_size;
	uint64_t	mac_pa0;
	uint64_t	mac_pa1;
};

struct tmi_mig_mem {
	struct tmi_mig_mem_data *data;
	uint64_t addr_and_size;
};

struct tmi_mig_memslot_data {
	uint64_t	dirty_bitmap_list[TMM_MAX_DIRTY_BITMAP_LEN];
	uint64_t	base_gfn;
	uint64_t	npages;
	short		memslot_id;
};

struct tmi_mig_memslot {
	struct tmi_mig_memslot_data *data;
	uint64_t addr_and_size;
};

struct virtCCAMigInfo {
	uint64_t swiotlb_start;
	uint64_t swiotlb_end;
};

enum slot_status {
	SLOT_IS_EMPTY = 0,
	SLOT_NOT_BINDED,
	SLOT_IS_BINDED,
	SLOT_IS_READY
};

/* vsock port for migvm */
#define MIGCVM_AGENT_PORT_SRC 9000
#define MIGCVM_AGENT_PORT_DST 9001

#define PAYLOAD_TYPE_ALL	  0
#define PAYLOAD_TYPE_CHAR	 1
#define PAYLOAD_TYPE_ULL	  2
#define VSOCK_MSG_ACK		 0xb
#define MAX_PAYLOAD_SIZE	  256

/* 1 bit aligned forced */
#pragma pack(push, 1)
struct socket_payload {
	char			char_payload[MAX_PAYLOAD_SIZE];
	unsigned long long ull_payload;
};
struct bind_msg_s {
	struct socket_payload payload;
	unsigned long long session_id;
	char			cmd[16];
	unsigned int	payload_type;
	unsigned int	payload_len;
	unsigned int	success;
};
#pragma pack(pop)

struct mig_cvm_update_info {
	uint64_t swiotlb_start;
	uint64_t swiotlb_end;
	uint64_t ipa_start;
};

#define SEC_MEM "secure"
#define NON_SEC_MEM "non-secure"

struct crc_config {
	uint64_t ipa_start;
	uint64_t ipa_end;
	uint64_t granularity;
	bool is_secure;
	bool enabled;
};

#endif

#endif
