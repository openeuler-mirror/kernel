/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * HYGON Platform Security Processor (PSP) driver interface
 *
 * Copyright (C) 2024 Hygon Info Technologies Ltd.
 *
 * Author: Liyang Han <hanliyang@hygon.cn>
 */

#ifndef __PSP_HYGON_H__
#define __PSP_HYGON_H__

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/kvm_types.h>
#include <uapi/linux/psp-hygon.h>

/*****************************************************************************/
/***************************** CSV interface *********************************/
/*****************************************************************************/

#define CSV_FW_MAX_SIZE		0x80000	/* 512KB */

#define CSV_EXT_CSV3_MULT_LUP_DATA_BIT	0
#define CSV_EXT_CSV3_MULT_LUP_DATA	(1 << CSV_EXT_CSV3_MULT_LUP_DATA_BIT)
#define CSV_EXT_CSV3_INJ_SECRET_BIT	1
#define CSV_EXT_CSV3_INJ_SECRET		(1 << CSV_EXT_CSV3_INJ_SECRET_BIT)

/**
 * Guest/platform management commands for CSV
 */
enum csv_cmd {
	CSV_CMD_RING_BUFFER		= 0x00F,
	CSV_CMD_HGSC_CERT_IMPORT        = 0x300,
	CSV_CMD_MAX,
};

/**
 * Guest/platform management commands for CSV3
 */
enum csv3_cmd {
	/* Guest launch commands */
	CSV3_CMD_SET_GUEST_PRIVATE_MEMORY	= 0x200,
	CSV3_CMD_LAUNCH_ENCRYPT_DATA		= 0x201,
	CSV3_CMD_LAUNCH_ENCRYPT_VMCB		= 0x202,
	CSV3_CMD_LAUNCH_FINISH_EX		= 0x204,
	/* Guest NPT(Nested Page Table) management commands */
	CSV3_CMD_UPDATE_NPT			= 0x203,

	/* Guest migration commands */
	CSV3_CMD_SEND_ENCRYPT_DATA		= 0x210,
	CSV3_CMD_SEND_ENCRYPT_CONTEXT		= 0x211,
	CSV3_CMD_RECEIVE_ENCRYPT_DATA		= 0x212,
	CSV3_CMD_RECEIVE_ENCRYPT_CONTEXT	= 0x213,

	/* Guest debug commands */
	CSV3_CMD_DBG_READ_VMSA			= 0x220,
	CSV3_CMD_DBG_READ_MEM			= 0x221,

	/* Platform secure memory management commands */
	CSV3_CMD_SET_SMR			= 0x230,
	CSV3_CMD_SET_SMCR			= 0x231,

	CSV3_CMD_MAX,
};

/**
 * CSV communication state
 */
enum csv_comm_state {
	CSV_COMM_MAILBOX_ON		= 0x0,
	CSV_COMM_RINGBUFFER_ON		= 0x1,

	CSV_COMM_MAX
};

/**
 * Ring Buffer Mode regions:
 *   There are 4 regions and every region is a 4K area that must be 4K aligned.
 *   To accomplish this allocate an amount that is the size of area and the
 *   required alignment.
 *   The aligned address will be calculated from the returned address.
 */
#define CSV_RING_BUFFER_SIZE		(32 * 1024)
#define CSV_RING_BUFFER_ALIGN		(4 * 1024)
#define CSV_RING_BUFFER_LEN		(CSV_RING_BUFFER_SIZE + CSV_RING_BUFFER_ALIGN)
#define CSV_RING_BUFFER_ESIZE		16
#define PSP_RING_BUFFER_OVERCOMMIT_SIZE		1024
#define CSV_RING_BUFFER_ELEMENT_NUM		(CSV_RING_BUFFER_SIZE / CSV_RING_BUFFER_ESIZE)

/**
 * struct csv_data_hgsc_cert_import - HGSC_CERT_IMPORT command parameters
 *
 * @hgscsk_cert_address: HGSCSK certificate chain
 * @hgscsk_cert_len: len of HGSCSK certificate
 * @hgsc_cert_address: HGSC certificate chain
 * @hgsc_cert_len: len of HGSC certificate
 */
struct csv_data_hgsc_cert_import {
	u64 hgscsk_cert_address;        /* In */
	u32 hgscsk_cert_len;            /* In */
	u32 reserved;                   /* In */
	u64 hgsc_cert_address;          /* In */
	u32 hgsc_cert_len;              /* In */
} __packed;

#define CSV_COMMAND_PRIORITY_HIGH	0
#define CSV_COMMAND_PRIORITY_LOW	1
#define CSV_COMMAND_PRIORITY_NUM	2

struct csv_cmdptr_entry {
	u16 cmd_id;
	u16 cmd_flags;
	u32 sw_data;
	u64 cmd_buf_ptr;
} __packed;

struct csv_statval_entry {
	u16 status;
	u16 reserved0;
	u32 reserved1;
	u64 reserved2;
} __packed;

struct csv_queue {
	u32 head;
	u32 tail;
	u32 mask; /* mask = (size - 1), inicates the elements max count */
	u32 esize; /* size of an element */
	u64 data;
	u64 data_align;
} __packed;

struct csv_ringbuffer_queue {
	struct csv_queue cmd_ptr;
	struct csv_queue stat_val;
} __packed;

/**
 * struct csv_data_ring_buffer - RING_BUFFER command parameters
 *
 * @queue_lo_cmdptr_address: physical address of the region to be used for
 *                           low priority queue's CmdPtr ring buffer
 * @queue_lo_statval_address: physical address of the region to be used for
 *                            low priority queue's StatVal ring buffer
 * @queue_hi_cmdptr_address: physical address of the region to be used for
 *                           high priority queue's CmdPtr ring buffer
 * @queue_hi_statval_address: physical address of the region to be used for
 *                            high priority queue's StatVal ring buffer
 * @queue_lo_size: size of the low priority queue in 4K pages. Must be 1
 * @queue_hi_size: size of the high priority queue in 4K pages. Must be 1
 * @queue_lo_threshold: queue(low) size, below which an interrupt may be generated
 * @queue_hi_threshold: queue(high) size, below which an interrupt may be generated
 * @int_on_empty: unconditionally interrupt when both queues are found empty
 */
struct csv_data_ring_buffer {
	u64 queue_lo_cmdptr_address;	/* In */
	u64 queue_lo_statval_address;	/* In */
	u64 queue_hi_cmdptr_address;	/* In */
	u64 queue_hi_statval_address;	/* In */
	u8 queue_lo_size;		/* In */
	u8 queue_hi_size;		/* In */
	u16 queue_lo_threshold;		/* In */
	u16 queue_hi_threshold;		/* In */
	u16 int_on_empty;		/* In */
} __packed;

/**
 * struct csv3_data_launch_encrypt_data - CSV3_CMD_LAUNCH_ENCRYPT_DATA command
 *
 * @handle: handle of the VM to update
 * @gpa: guest address where data is copied
 * @length: len of memory to be encrypted
 * @data_blocks: memory regions to hold data page address
 */
struct csv3_data_launch_encrypt_data {
	u32 handle;			/* In */
	u32 reserved;			/* In */
	u64 gpa;			/* In */
	u32 length;			/* In */
	u32 reserved1;			/* In */
	u64 data_blocks[8];		/* In */
} __packed;

/**
 * struct csv3_data_launch_encrypt_vmcb - CSV3_CMD_LAUNCH_ENCRYPT_VMCB command
 *
 * @handle: handle of the VM
 * @vcpu_id: id of vcpu per vmsa/vmcb
 * @vmsa_addr: memory address of initial vmsa data
 * @vmsa_len: len of initial vmsa data
 * @shadow_vmcb_addr: memory address of shadow vmcb data
 * @shadow_vmcb_len: len of shadow vmcb data
 * @secure_vmcb_addr: memory address of secure vmcb data
 * @secure_vmcb_len: len of secure vmcb data
 */
struct csv3_data_launch_encrypt_vmcb {
	u32 handle;			/* In */
	u32 reserved;			/* In */
	u32 vcpu_id;			/* In */
	u32 reserved1;			/* In */
	u64 vmsa_addr;			/* In */
	u32 vmsa_len;			/* In */
	u32 reserved2;			/* In */
	u64 shadow_vmcb_addr;		/* In */
	u32 shadow_vmcb_len;		/* In */
	u32 reserved3;			/* In */
	u64 secure_vmcb_addr;		/* Out */
	u32 secure_vmcb_len;		/* Out */
} __packed;

/**
 * struct csv3_data_launch_finish_ex - CSV3_CMD_LAUNCH_FINISH_EX command
 *
 * @handle: handle assigned to the VM
 * @reserved0: reserved field, for future use
 * @host_data: the host supplied data
 * @reserved1: reserved field, for future use
 */
struct csv3_data_launch_finish_ex {
	u32 handle;			/* In */
	u32 reserved0;			/* In */
	u8  host_data[64];		/* In */
	u8  reserved1[184];		/* In */
} __packed;

/**
 * struct csv3_data_update_npt - CSV3_CMD_UPDATE_NPT command
 *
 * @handle: handle assigned to the VM
 * @error_code: nested page fault error code
 * @gpa: guest page address where npf happens
 * @spa: physical address which maps to gpa in host page table
 * @level: page level which can be mapped in nested page table
 * @page_attr: page attribute for gpa
 * @page_attr_mask: which page attribute bit should be set
 * @npages: number of pages from gpa is handled.
 */
struct csv3_data_update_npt {
	u32 handle;			/* In */
	u32 reserved;			/* In */
	u32 error_code;			/* In */
	u32 reserved1;			/* In */
	u64 gpa;			/* In */
	u64 spa;			/* In */
	u64 level;			/* In */
	u64 page_attr;			/* In */
	u64 page_attr_mask;		/* In */
	u32 npages;			/* In/Out */
} __packed;

/**
 * struct csv3_data_mem_region - define a memory region
 *
 * @base_address: base address of a memory region
 * @size: size of memory region
 */
struct csv3_data_memory_region {
	u64 base_address;		/* In */
	u64 size;			/* In */
} __packed;

/**
 * struct csv3_data_set_guest_private_memory - CSV3_CMD_SET_GUEST_PRIVATE_MEMORY
 * command parameters
 *
 * @handle: handle assigned to the VM
 * @nregions: number of memory regions
 * @regions_paddr: address of memory containing multiple memory regions
 */
struct csv3_data_set_guest_private_memory {
	u32 handle;			/* In */
	u32 nregions;			/* In */
	u64 regions_paddr;		/* In */
} __packed;

/**
 * struct csv3_data_set_smr - CSV3_CMD_SET_SMR command parameters
 *
 * @smr_entry_size: size of SMR entry
 * @nregions: number of memory regions
 * @regions_paddr: address of memory containing multiple memory regions
 */
struct csv3_data_set_smr {
	u32 smr_entry_size;		/* In */
	u32 nregions;			/* In */
	u64 regions_paddr;		/* In */
} __packed;

/**
 * struct csv3_data_set_smcr - CSV3_CMD_SET_SMCR command parameters
 *
 * @base_address: start address of SMCR memory
 * @size: size of SMCR memory
 */
struct csv3_data_set_smcr {
	u64 base_address;		/* In */
	u64 size;			/* In */
} __packed;

/**
 * struct csv3_data_dbg_read_vmsa - CSV3_CMD_DBG_READ_VMSA command parameters
 *
 * @handle: handle assigned to the VM
 * @spa: system physical address of memory to get vmsa of the specific vcpu
 * @size: size of the host memory
 * @vcpu_id: the specific vcpu
 */
struct csv3_data_dbg_read_vmsa {
	u32 handle;			/* In */
	u32 reserved;			/* In */
	u64 spa;			/* In */
	u32 size;			/* In */
	u32 vcpu_id;			/* In */
} __packed;

/**
 * struct csv3_data_dbg_read_mem - CSV3_CMD_DBG_READ_MEM command parameters
 *
 * @handle: handle assigned to the VM
 * @gpa: guest physical address of the memory to access
 * @spa: system physical address of memory to get data from gpa
 * @size: size of guest memory to access
 */
struct csv3_data_dbg_read_mem {
	u32 handle;			/* In */
	u32 reserved;			/* In */
	u64 gpa;			/* In */
	u64 spa;			/* In */
	u32 size;			/* In */
} __packed;

/**
 * struct csv3_data_attestation_report - ATTESTATION secure call command parameters
 *
 * @handle: handle of the VM to process
 * @flags: the bit flags used to indicate how to extend the attestation report.
 *	   It's copied from user space's parameter before issuing the ATTESTATION
 *	   secure call command.
 * @resp_gpa: guest physical address to save the generated report
 * @resp_length: length of the generated report
 * @req_gpa: guest physical address of the input for the report
 * @req_length: length of the input for the report
 * @fw_error_code: firmware status code when generating the report
 */
struct csv3_data_attestation_report {
	u32 handle;				/* Out */
	u32 flags;				/* In */
	u64 resp_gpa;				/* In */
	u8 reserved2[16];
	u32 resp_len;				/* In/Out */
	u32 reserved3;
	u64 req_gpa;				/* In */
	u32 req_len;				/* In,Out */
	u32 fw_error_code;			/* Out */
} __packed;

/**
 * struct csv3_data_send_encrypt_data - SEND_ENCRYPT_DATA command parameters
 *
 * @handle: handle of the VM to process
 * @hdr_address: physical address containing packet header
 * @hdr_len: len of packet header
 * @guest_block: physical address containing multiple guest address
 * @guest_len: len of guest block
 * @flag: flag of send encrypt data
 *        0x00000000: migrate pages in guest block
 *        0x00000001: set readonly of pages in guest block
 *            others: invalid
 * @trans_block: physical address of a page containing multiple host memory pages
 * @trans_len: len of host memory region
 */
struct csv3_data_send_encrypt_data {
	u32 handle;			/* In */
	u32 reserved;			/* In */
	u64 hdr_address;		/* In */
	u32 hdr_len;			/* In/Out */
	u32 reserved1;			/* In */
	u64 guest_block;		/* In */
	u32 guest_len;			/* In */
	u32 flag;			/* In */
	u64 trans_block;		/* In */
	u32 trans_len;			/* In/Out */
} __packed;

/**
 * struct csv3_data_send_encrypt_context - SEND_ENCRYPT_CONTEXT command parameters
 *
 * @handle: handle of the VM to process
 * @hdr_address: physical address containing packet header
 * @hdr_len: len of packet header
 * @trans_block: physical address of a page containing multiple host memory pages
 * @trans_len: len of host memory region
 */
struct csv3_data_send_encrypt_context {
	u32 handle;			/* In */
	u32 reserved;			/* In */
	u64 hdr_address;		/* In */
	u32 hdr_len;			/* In/Out */
	u32 reserved1;			/* In */
	u64 trans_block;		/* In */
	u32 trans_len;			/* In/Out */
} __packed;

/**
 * struct csv3_data_receive_encrypt_data - RECEIVE_ENCRYPT_DATA command parameters
 *
 * @handle: handle of the VM to process
 * @hdr_address: physical address containing packet header blob
 * @hdr_len: len of packet header
 * @guest_block: system physical address containing multiple guest address
 * @guest_len: len of guest block memory region
 * @trans_block: physical address of a page containing multiple host memory pages
 * @trans_len: len of host memory region
 */
struct csv3_data_receive_encrypt_data {
	u32 handle;			/* In */
	u32 reserved;			/* In */
	u64 hdr_address;		/* In */
	u32 hdr_len;			/* In */
	u32 reserved1;			/* In */
	u64 guest_block;		/* In */
	u32 guest_len;			/* In */
	u32 reserved2;			/* In */
	u64 trans_block;		/* In */
	u32 trans_len;			/* In */
} __packed;

/**
 * struct csv3_data_receive_encrypt_context - RECEIVE_ENCRYPT_CONTEXT command parameters
 *
 * @handle: handle of the VM to process
 * @hdr_address: physical address containing packet header
 * @hdr_len: len of packet header
 * @trans_block: physical address of a page containing multiple host memory pages
 * @trans_len: len of host memory region
 * @shadow_vmcb_block: physical address of a page containing multiple shadow vmcb address
 * @secure_vmcb_block: physical address of a page containing multiple secure vmcb address
 * @vmcb_block_len: len of shadow/secure vmcb block
 */
struct csv3_data_receive_encrypt_context {
	u32 handle;			/* In */
	u32 reserved;			/* In */
	u64 hdr_address;		/* In */
	u32 hdr_len;			/* In */
	u32 reserved1;			/* In */
	u64 trans_block;		/* In */
	u32 trans_len;			/* In */
	u32 reserved2;			/* In */
	u64 shadow_vmcb_block;		/* In */
	u64 secure_vmcb_block;		/* In */
	u32 vmcb_block_len;		/* In */
} __packed;

/*
 ****************************** CSV3 secure call *******************************
 *
 * CSV3 guest is based on hygon secure isolated virualization feature. An secure
 * processor which resides in hygon SOC manages guest's private memory. The
 * secure processor allocates or frees private memory for CSV3 guest and manages
 * CSV3 guest's nested page table.
 *
 * As the secure processor is considered as a PCI device in host, CSV3 guest can
 * not communicate with it directly. Howerver, CSV3 guest must request the secure
 * processor to change its physical memory between private memory and shared
 * memory. CSV3 secure call command is a method used to communicate with secure
 * processor that host cannot tamper with the data in CSV3 guest. Host can only
 * perform an external command to notify the secure processor to handle the
 * pending guest's command.
 *
 * CSV3 secure call pages:
 * Secure call pages are two dedicated pages that reserved by BIOS. We define
 * secure call pages as page A and page B. During guest launch stage, the secure
 * processor will parse the address of secure call pages. The secure processor
 * maps the two pages with same private memory page in NPT. The secure processor
 * always set one page as present and another page as non-present in NPT.

 * CSV3 secure call main work flow:
 * If we write the guest's commands in one page then read them from another page,
 * nested page fault happens and the guest exits to host. Then host will perform
 * an external command with the gpa(page A or page B) to the secure processor.
 * The secure processor checks that the gpa in NPF belongs to secure call pages,
 * read the guest's command to handle, then switch the present bit between the
 * two pages.
 *
 *			guest page A    guest page B
 *			      |              |
 *			  ____|______________|____
 *			  |                      |
 *			  |  nested page table   |
 *			  |______________________|
 *			      \              /
 *			       \            /
 *			        \          /
 *			         \        /
 *			          \      /
 *			       secure memory page
 *
 * CSV3_SECURE_CMD_ENC:
 *	CSV3 guest declares a specifid memory range as secure. By default, all of
 *	CSV3 guest's memory mapped as secure.
 *	The secure processor allocate a block of secure memory and map the memory
 *	in CSV3 guest's NPT with the specified guest physical memory range in CSV3
 *	secure call.
 *
 * CSV3_SECURE_CMD_DEC:
 *	CSV3 guest declares a specified memory range as shared.
 *	The secure processor save the guest physical memory range in its own ram
 *	and free the range in CSV3 guest's NPT. When CSV3 guest access the memory,
 *	a new nested page fault happens.
 *
 * CSV3_SECURE_CMD_RESET:
 *	CSV3 guest switches all of the shared memory to secure.
 *	The secure processor resets all the shared memory in CSV3 guest's NPT and
 *	clears the saved shared memory range. Then the secure process allocates
 *	secure memory to map in CSV3 guest's NPT.
 *
 * CSV3_SECURE_CMD_UPDATE_SECURE_CALL_TABLE:
 *	CSV3 guest wants to change the secure call pages.
 *	The secure processor re-init the secure call context.
 *
 * CSV3_SECURE_CMD_REQ_REPORT:
 *      CSV3 guest wants to request attestation report.
 *      The secure processor will update the request message buffer and respond
 *      buffer to indicate the result of this request.
 */
enum csv3_secure_command_type {
	/* The secure call request should below CSV3_SECURE_CMD_ACK */
	CSV3_SECURE_CMD_ENC			= 0x1,
	CSV3_SECURE_CMD_DEC,
	CSV3_SECURE_CMD_RESET,
	CSV3_SECURE_CMD_UPDATE_SECURE_CALL_TABLE,
	CSV3_SECURE_CMD_REQ_REPORT		= 0x7,
	CSV3_SECURE_CMD_RTMR,

	/* SECURE_CMD_ACK indicates secure call request can be handled */
	CSV3_SECURE_CMD_ACK			= 0x6b,

	/*
	 * The following values are the error code of the secure call
	 * when firmware can't handling the specific secure call command
	 * as expected.
	 */
	CSV3_SECURE_CMD_ERROR_INTERNAL		= 0x6c,
	CSV3_SECURE_CMD_ERROR_INVALID_COMMAND	= 0x6d,
	CSV3_SECURE_CMD_ERROR_INVALID_PARAM	= 0x6e,
	CSV3_SECURE_CMD_ERROR_INVALID_ADDRESS	= 0x6f,
	CSV3_SECURE_CMD_ERROR_INVALID_LENGTH	= 0x70,
};

/*
 * CSV3_SECURE_CMD_RTMR's subcommand.
 *
 * CSV3_SECURE_CMD_RTMR_STATUS:
 *     Get the RTMR status info of the CSV3 guest.
 * CSV3_SECURE_CMD_RTMR_START:
 *     Negotiate/Start the RTMR.
 * CSV3_SECURE_CMD_RTMR_READ:
 *     Read RTMR registers.
 * CSV3_SECURE_CMD_RTMR_EXTEND:
 *     Extend a specific RTMR register.
 */
enum csv3_secure_command_rtmr_subtype {
	CSV3_SECURE_CMD_RTMR_STATUS	= 0x1,
	CSV3_SECURE_CMD_RTMR_START	= 0x2,
	CSV3_SECURE_CMD_RTMR_READ	= 0x3,
	CSV3_SECURE_CMD_RTMR_EXTEND	= 0x4,
};

/**
 * struct csv_rtmr_subcmd_hdr - Common header structure for RTMR subcommands
 *
 * @subcmd_id: identifier of the subcommand
 * @subcmd_size: the size of the subcommand buffer
 * @fw_error_code: the return code of subcommand
 */
struct csv_rtmr_subcmd_hdr {
	uint16_t subcmd_id;	/* In */
	uint16_t subcmd_size;	/* In,Out */
	uint32_t fw_error_code;	/* Out */
} __packed;

/**
 * struct csv_rtmr_subcmd_status - RTMR_STATUS subcommand parameters
 *
 * @hdr: common structure used for RTMR subcommands
 * @version: the RTMR version used in the guest. When in state
 *	     RTMR_STATE_INIT, it will be fixed.
 * @state: the state of the guest's RTMR.
 * @reserved: reserved
 */
struct csv_rtmr_subcmd_status {
	struct csv_rtmr_subcmd_hdr hdr;	/* In,Out */
	uint16_t version;		/* Out */
	uint8_t state;			/* Out */
	uint8_t reserved[21];		/* reserved */
} __packed;

/**
 * struct csv_rtmr_subcmd_start - RTMR_START subcommand parameters
 *
 * @hdr: common structure used for RTMR subcommands
 * @version: the RTMR version requested by the guest
 * @reserved: reserved
 */
struct csv_rtmr_subcmd_start {
	struct csv_rtmr_subcmd_hdr hdr;	/* In,Out */
	uint16_t version;		/* In,Out */
	uint8_t reserved[22];		/* reserved */
} __packed;

/**
 * struct csv_rtmr_subcmd_read - RTMR_READ subcommand parameters
 *
 * @hdr: common structure used for RTMR subcommands
 * @rtmr_reg_bitmap: the bitmap specified the RTMR registers to read
 * @reserved: reserved
 * @data: the buffer to store data of the specified RTMR registers
 */
struct csv_rtmr_subcmd_read {
	struct csv_rtmr_subcmd_hdr hdr;		/* In,Out */
	uint32_t rtmr_reg_bitmap;		/* In,Out */
	uint8_t  reserved[20];			/* reserved */
	uint8_t data[CSV_RTMR_REG_SIZE];	/* Out */
} __packed;

/**
 * struct csv_rtmr_subcmd_extend - RTMR_EXTEND subcommand parameters
 *
 * @hdr: common structure used for RTMR subcommands
 * @index: the index for extending the RTMR register
 * @reserved1: reserved
 * @data_length: the length of the data to be extended
 * @reserved2: reserved
 * @data: the data to be extended to the RTMR register
 */
struct csv_rtmr_subcmd_extend {
	struct csv_rtmr_subcmd_hdr hdr;		/* In,Out */
	uint8_t index;				/* In,Out */
	uint8_t reserved1;			/* reserved */
	uint16_t data_length;			/* In,Out */
	uint8_t reserved2[20];			/* reserved */
	uint8_t data[CSV_RTMR_EXTEND_LEN];	/* In */
} __packed;

/* csv3 secure call guid, do not change the value. */
#define CSV3_SECURE_CALL_GUID_LOW	0xceba2fa59a5d926ful
#define CSV3_SECURE_CALL_GUID_HIGH	0xa556555d276b21abul

/*
 * Secure call page fields.
 * Secure call page size is 4KB always. We define CSV3 secure call page structure
 * as below.
 * guid:	Must be in the first 128 bytes of the page. Its value should be
 *		(0xceba2fa59a5d926ful, 0xa556555d276b21abul) always.
 * cmd_type:	Command to be issued to the secure processor.
 * nums:	number of entries in the command.
 * base_address:Start address of the memory range.
 * size:	Size of the memory range.
 */
#define SECURE_CALL_ENTRY_MAX	(254)

/* size of secure call cmd is 4KB. */
struct csv3_secure_call_cmd {
	union {
		u8	guid[16];
		u64	guid_64[2];
	};
	u32	cmd_type;
	u32	nums;
	u64	unused;
	union {
		struct {
			u64	base_address;
			u64	size;
		} entry[SECURE_CALL_ENTRY_MAX];
		union {
			struct csv_rtmr_subcmd_hdr hdr;
			struct csv_rtmr_subcmd_status status_cmd;
			struct csv_rtmr_subcmd_read read_cmd;
			struct csv_rtmr_subcmd_extend extend_cmd;
		} csv_rtmr_subcmd;
	};
} __packed;

struct kvm_vpsp {
	struct kvm *kvm;
	int (*write_guest)(struct kvm *kvm, gpa_t gpa, const void *data, unsigned long len);
	int (*read_guest)(struct kvm *kvm, gpa_t gpa, void *data, unsigned long len);
	kvm_pfn_t (*gfn_to_pfn)(struct kvm *kvm, gfn_t gfn);
	u32 vm_handle;
	u8 is_csv_guest;
};

#ifdef CONFIG_CRYPTO_DEV_SP_PSP

int psp_do_cmd(int cmd, void *data, int *psp_ret);

int csv_ring_buffer_queue_init(void);
int csv_ring_buffer_queue_free(void);
int csv_fill_cmd_queue(int prio, int cmd, void *data, uint16_t flags);
int csv_check_stat_queue_status(int *psp_ret);

/**
 * csv_issue_ringbuf_cmds_external_user - issue CSV commands into a ring
 * buffer.
 */
int csv_issue_ringbuf_cmds_external_user(struct file *filep, int *psp_ret);

int kvm_pv_psp_copy_forward_op(struct kvm_vpsp *vpsp, int cmd, gpa_t data_gpa, gpa_t psp_ret_gpa);

int kvm_pv_psp_forward_op(struct kvm_vpsp *vpsp, uint32_t cmd,
				gpa_t data_gpa, uint32_t psp_ret);

/**
 * csv_get_extension_info - collect extension set of the firmware
 *
 * @buf: The buffer to save extension set
 * @size: The size of the @buf
 *
 * Returns:
 * 0 if @buf is filled with extension bitflags
 * -%ENODEV if the CSV device is not available
 * -%EINVAL if @buf is NULL or @size is too smaller
 */
int csv_get_extension_info(void *buf, size_t *size);

#else	/* !CONFIG_CRYPTO_DEV_SP_PSP */

static inline int psp_do_cmd(int cmd, void *data, int *psp_ret) { return -ENODEV; }

static inline int csv_ring_buffer_queue_init(void) { return -ENODEV; }
static inline int csv_ring_buffer_queue_free(void) { return -ENODEV; }
static inline
int csv_fill_cmd_queue(int prio, int cmd, void *data, uint16_t flags) { return -ENODEV; }
static inline int csv_check_stat_queue_status(int *psp_ret) { return -ENODEV; }
static inline int
csv_issue_ringbuf_cmds_external_user(struct file *filep, int *psp_ret) { return -ENODEV; }

static inline int
kvm_pv_psp_copy_forward_op(struct kvm_vpsp *vpsp, int cmd, gpa_t data_gpa,
				gpa_t psp_ret_gpa) { return -ENODEV; }

static inline int
kvm_pv_psp_forward_op(struct kvm_vpsp *vpsp, uint32_t cmd,
			gpa_t data_gpa, uint32_t psp_ret) { return -ENODEV; }

static inline int csv_get_extension_info(void *buf, size_t *size) { return -ENODEV; }

#endif	/* CONFIG_CRYPTO_DEV_SP_PSP */

typedef int (*p2c_notifier_t)(uint32_t id, uint64_t data);

#ifdef CONFIG_HYGON_PSP2CPU_CMD

int psp_register_cmd_notifier(uint32_t cmd_id, p2c_notifier_t notifier);
int psp_unregister_cmd_notifier(uint32_t cmd_id, p2c_notifier_t notifier);

#else	/* !CONFIG_HYGON_PSP2CPU_CMD */

static inline
int psp_register_cmd_notifier(uint32_t cmd_id, p2c_notifier_t notifier) { return -ENODEV; }
static inline
int psp_unregister_cmd_notifier(uint32_t cmd_id, p2c_notifier_t notifier) { return -ENODEV; }

#endif	/* CONFIG_HYGON_PSP2CPU_CMD */

#endif	/* __PSP_HYGON_H__ */
