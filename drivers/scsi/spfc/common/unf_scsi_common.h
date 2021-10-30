/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef UNF_SCSI_COMMON_H
#define UNF_SCSI_COMMON_H

#include "unf_type.h"

#define SCSI_SENSE_DATA_LEN 96
#define DRV_SCSI_CDB_LEN 16
#define DRV_SCSI_LUN_LEN 8

#define DRV_ENTRY_PER_SGL 64 /* Size of an entry array in a hash table */

#define UNF_DIF_AREA_SIZE (8)

struct unf_dif_control_info {
	u16 app_tag;
	u16 flags;
	u32 protect_opcode;
	u32 fcp_dl;
	u32 start_lba;
	u8 actual_dif[UNF_DIF_AREA_SIZE];
	u8 expected_dif[UNF_DIF_AREA_SIZE];
	u32 dif_sge_count;
	void *dif_sgl;
};

struct dif_result_info {
	unsigned char actual_idf[UNF_DIF_AREA_SIZE];
	unsigned char expect_dif[UNF_DIF_AREA_SIZE];
};

struct drv_sge {
	char *buf;
	void *page_ctrl;
	u32 Length;
	u32 offset;
};

struct drv_scsi_cmd_result {
	u32 Status;
	u16 sense_data_length;		    /* sense data length */
	u8 sense_data[SCSI_SENSE_DATA_LEN]; /* fail sense info */
};

enum drv_io_direction {
	DRV_IO_BIDIRECTIONAL = 0,
	DRV_IO_DIRECTION_WRITE = 1,
	DRV_IO_DIRECTION_READ = 2,
	DRV_IO_DIRECTION_NONE = 3,
};

struct drv_sgl {
	struct drv_sgl *next_sgl; /* poin to SGL,SGL list */
	unsigned short num_sges_in_chain;
	unsigned short num_sges_in_sgl;
	u32 flag;
	u64 serial_num;
	struct drv_sge sge[DRV_ENTRY_PER_SGL];
	struct list_head node;
	u32 cpu_id;
};

struct dif_info {
/* Indicates the result returned when the data protection
 *information is inconsistent,add by pangea
 */
	struct dif_result_info dif_result;
/* Data protection information operation code
 * bit[31-24] other operation code
 * bit[23-16] Data Protection Information Operation
 * bit[15-8] Data protection information
 * verification bit[7-0] Data protection information
 * replace
 */
	u32 protect_opcode;
	unsigned short apptag;
	u64 start_lba; /* IO start LBA */
	struct drv_sgl *protection_sgl;
};

struct drv_device_address {
	u16 initiator_id; /* ini id */
	u16 bus_id;	  /* device bus id */
	u16 target_id;	  /* device target id,for PCIe SSD,device id */
	u16 function_id;  /* function id */
};

struct drv_ini_cmd {
	struct drv_scsi_cmd_result result;
	void *upper;		  /* product private pointer */
	void *lower;		  /* driver private pointer */
	u8 cdb[DRV_SCSI_CDB_LEN]; /* CDB edit by product */
	u8 lun[DRV_SCSI_LUN_LEN];
	u16 cmd_len;
	u16 tag;		/* SCSI cmd add by driver */
	enum drv_io_direction io_direciton;
	u32 data_length;
	u32 underflow;
	u32 overflow;
	u32 resid;
	u64 port_id;
	u64 cmd_sn;
	struct drv_device_address addr;
	struct drv_sgl *sgl;
	void *device;
	void (*done)(struct drv_ini_cmd *cmd); /* callback pointer */
	struct dif_info dif_info;
};

typedef void (*uplevel_cmd_done)(struct drv_ini_cmd *scsi_cmnd);

#ifndef SUCCESS
#define SUCCESS 0x2002
#endif
#ifndef FAILED
#define FAILED 0x2003
#endif

#ifndef DRIVER_OK
#define DRIVER_OK 0x00 /* Driver status */
#endif

#ifndef PCI_FUNC
#define PCI_FUNC(devfn) ((devfn) & 0x07)
#endif

#define UNF_SCSI_ABORT_SUCCESS SUCCESS
#define UNF_SCSI_ABORT_FAIL FAILED

#define UNF_SCSI_STATUS(byte) (byte)
#define UNF_SCSI_MSG(byte) ((byte) << 8)
#define UNF_SCSI_HOST(byte) ((byte) << 16)
#define UNF_SCSI_DRIVER(byte) ((byte) << 24)
#define UNF_GET_SCSI_HOST_ID(scsi_host) ((scsi_host)->host_no)

struct unf_ini_error_code {
	u32 drv_errcode; /* driver error code */
	u32 ap_errcode;	 /* up level error code */
};

typedef u32 (*ini_get_sgl_entry_buf)(void *upper_cmnd, void *driver_sgl,
				     void **upper_sgl, u32 *req_index,
				     u32 *index, char **buf,
				     u32 *buf_len);

#define UNF_SCSI_SENSE_BUFFERSIZE 96
struct unf_scsi_cmnd {
	u32 scsi_host_id;
	u32 scsi_id; /* cmd->dev->id */
	u64 raw_lun_id;
	u64 port_id;
	u32 under_flow;	  /* Underflow */
	u32 transfer_len; /* Transfer Length */
	u32 resid;	  /* Resid */
	u32 sense_buflen;
	int result;
	u32 entry_count; /* IO Buffer counter */
	u32 abort;
	u32 err_code_table_cout; /* error code size */
	u64 cmnd_sn;
	ulong time_out;	   /* EPL driver add timer */
	u16 cmnd_len;	   /* Cdb length */
	u8 data_direction; /* data direction */
	u8 *pcmnd;	   /* SCSI CDB */
	u8 *sense_buf;
	void *drv_private;     /* driver host pionter */
	void *driver_scribble; /* Xchg pionter */
	void *upper_cmnd;      /* UpperCmnd pointer by driver */
	u8 *lun_id;	       /* new lunid */
	u32 world_id;
	struct unf_dif_control_info dif_control;   /* DIF control */
	struct unf_ini_error_code *err_code_table; /* error code table */
	void *sgl;				   /* Sgl pointer */
	ini_get_sgl_entry_buf unf_ini_get_sgl_entry;
	void (*done)(struct unf_scsi_cmnd *cmd);
	uplevel_cmd_done uplevel_done;
	struct dif_info dif_info;
	u32 qos_level;
	void *pinitiator;
};

#ifndef FC_PORTSPEED_32GBIT
#define FC_PORTSPEED_32GBIT 0x40
#endif

#define UNF_GID_PORT_CNT 2048
#define UNF_RSCN_PAGE_SUM 255

#define UNF_CPU_ENDIAN

#define UNF_NPORTID_MASK 0x00FFFFFF
#define UNF_DOMAIN_MASK 0x00FF0000
#define UNF_AREA_MASK 0x0000FF00
#define UNF_ALPA_MASK 0x000000FF

struct unf_fc_head {
	u32 rctl_did;  /* Routing control and Destination address of the seq */
	u32 csctl_sid; /* Class control and Source address of the sequence */
	u32 type_fctl; /* Data type and Initial frame control value of the seq
			*/
	u32 seqid_dfctl_seqcnt; /* Seq ID, Data Field and Initial seq count */
	u32 oxid_rxid; /* Originator & Responder exchange IDs for the sequence
			*/
	u32 parameter; /* Relative offset of the first frame of the sequence */
};

#define UNF_FCPRSP_CTL_LEN (24)
#define UNF_MAX_RSP_INFO_LEN (8)
#define UNF_RSP_LEN_VLD (1 << 0)
#define UNF_SENSE_LEN_VLD (1 << 1)
#define UNF_RESID_OVERRUN (1 << 2)
#define UNF_RESID_UNDERRUN (1 << 3)
#define UNF_FCP_CONF_REQ (1 << 4)

/* T10: FCP2r.07 9.4.1 Overview and format of FCP_RSP IU */
struct unf_fcprsp_iu {
	u32 reserved[2];
	u8 reserved2[2];
	u8 control;
	u8 fcp_status;
	u32 fcp_residual;
	u32 fcp_sense_len;    /* Length of sense info field */
	u32 fcp_response_len; /* Length of response info field in bytes 0,4 or 8
			       */
	u8 fcp_resp_info[UNF_MAX_RSP_INFO_LEN]; /* Buffer for response info */
	u8 fcp_sense_info[SCSI_SENSE_DATA_LEN]; /* Buffer for sense info */
} __attribute__((packed));

#define UNF_CMD_REF_MASK 0xFF000000
#define UNF_TASK_ATTR_MASK 0x00070000
#define UNF_TASK_MGMT_MASK 0x0000FF00
#define UNF_FCP_WR_DATA 0x00000001
#define UNF_FCP_RD_DATA 0x00000002
#define UNF_CDB_LEN_MASK 0x0000007C
#define UNF_FCP_CDB_LEN_16 (16)
#define UNF_FCP_CDB_LEN_32 (32)
#define UNF_FCP_LUNID_LEN_8 (8)

/* FCP-4 :Table 27 - RSP_CODE field */
#define UNF_FCP_TM_RSP_COMPLETE (0)
#define UNF_FCP_TM_INVALID_CMND (0x2)
#define UNF_FCP_TM_RSP_REJECT (0x4)
#define UNF_FCP_TM_RSP_FAIL (0x5)
#define UNF_FCP_TM_RSP_SUCCEED (0x8)
#define UNF_FCP_TM_RSP_INCRECT_LUN (0x9)

#define UNF_SET_TASK_MGMT_FLAGS(fcp_tm_code) ((fcp_tm_code) << 8)
#define UNF_GET_TASK_MGMT_FLAGS(control) (((control) & UNF_TASK_MGMT_MASK) >> 8)

enum unf_task_mgmt_cmd {
	UNF_FCP_TM_QUERY_TASK_SET = (1 << 0),
	UNF_FCP_TM_ABORT_TASK_SET = (1 << 1),
	UNF_FCP_TM_CLEAR_TASK_SET = (1 << 2),
	UNF_FCP_TM_QUERY_UNIT_ATTENTION = (1 << 3),
	UNF_FCP_TM_LOGICAL_UNIT_RESET = (1 << 4),
	UNF_FCP_TM_TARGET_RESET = (1 << 5),
	UNF_FCP_TM_CLEAR_ACA = (1 << 6),
	UNF_FCP_TM_TERMINATE_TASK = (1 << 7) /* obsolete */
};

struct unf_fcp_cmnd {
	u8 lun[UNF_FCP_LUNID_LEN_8]; /* Logical unit number */
	u32 control;
	u8 cdb[UNF_FCP_CDB_LEN_16]; /* Payload data containing cdb info */
	u32 data_length; /* Number of bytes expected to be transferred */
} __attribute__((packed));

struct unf_fcp_cmd_hdr {
	struct unf_fc_head frame_hdr; /* FCHS structure */
	struct unf_fcp_cmnd fcp_cmnd; /* Fcp Cmnd struct */
};

/* FC-LS-2 Common Service Parameter applicability */
struct unf_fabric_coparm {
#if defined(UNF_CPU_ENDIAN)
	u32 bb_credit : 16;	 /* 0 [0-15] */
	u32 lowest_version : 8;	 /* 0 [16-23] */
	u32 highest_version : 8; /* 0 [24-31] */
#else
	u32 highest_version : 8;	  /* 0 [24-31] */
	u32 lowest_version : 8;		  /* 0 [16-23] */
	u32 bb_credit : 16;		  /* 0 [0-15] */
#endif

#if defined(UNF_CPU_ENDIAN)
	u32 bb_receive_data_field_size : 12; /* 1 [0-11] */
	u32 bbscn : 4;			     /* 1 [12-15] */
	u32 payload_length : 1;		     /* 1 [16] */
	u32 seq_cnt : 1;		     /* 1 [17] */
	u32 dynamic_half_duplex : 1;	     /* 1 [18] */
	u32 r_t_tov : 1;		     /* 1 [19] */
	u32 reserved_co2 : 6;		     /* 1 [20-25] */
	u32 e_d_tov_resolution : 1;	     /* 1 [26] */
	u32 alternate_bb_credit_mgmt : 1;    /* 1 [27] */
	u32 nport : 1;			     /* 1 [28] */
	u32 mnid_assignment : 1;	     /* 1 [29] */
	u32 random_relative_offset : 1;	     /* 1 [30] */
	u32 clean_address : 1;		     /* 1 [31] */
#else
	u32 reserved_co2 : 2;		  /* 1 [24-25] */
	u32 e_d_tov_resolution : 1;	  /* 1 [26] */
	u32 alternate_bb_credit_mgmt : 1; /* 1 [27] */
	u32 nport : 1;			  /* 1 [28] */
	u32 mnid_assignment : 1;	  /* 1 [29] */
	u32 random_relative_offset : 1;	  /* 1 [30] */
	u32 clean_address : 1;		  /* 1 [31] */

	u32 payload_length : 1;	     /* 1 [16] */
	u32 seq_cnt : 1;	     /* 1 [17] */
	u32 dynamic_half_duplex : 1; /* 1 [18] */
	u32 r_t_tov : 1;	     /* 1 [19] */
	u32 reserved_co5 : 4;	     /* 1 [20-23] */

	u32 bb_receive_data_field_size : 12; /* 1 [0-11] */
	u32 bbscn : 4;			     /* 1 [12-15] */
#endif
	u32 r_a_tov; /* 2 [0-31] */
	u32 e_d_tov; /* 3 [0-31] */
};

/* FC-LS-2  Common Service Parameter applicability */
/*Common Service Parameters - PLOGI and PLOGI LS_ACC */
struct lgn_port_coparm {
#if defined(UNF_CPU_ENDIAN)
	u32 bb_credit : 16;	 /* 0 [0-15] */
	u32 lowest_version : 8;	 /* 0 [16-23] */
	u32 highest_version : 8; /* 0 [24-31] */
#else
	u32 highest_version : 8;	     /* 0 [24-31] */
	u32 lowest_version : 8;		     /* 0 [16-23] */
	u32 bb_credit : 16;		     /* 0 [0-15] */
#endif

#if defined(UNF_CPU_ENDIAN)
	u32 bb_receive_data_field_size : 12; /* 1 [0-11] */
	u32 bbscn : 4;			     /* 1 [12-15] */
	u32 payload_length : 1;		     /* 1 [16] */
	u32 seq_cnt : 1;		     /* 1 [17] */
	u32 dynamic_half_duplex : 1;	     /* 1 [18] */
	u32 reserved_co2 : 7;		     /* 1 [19-25] */
	u32 e_d_tov_resolution : 1;	     /* 1 [26] */
	u32 alternate_bb_credit_mgmt : 1;    /* 1 [27] */
	u32 nport : 1;			     /* 1 [28] */
	u32 vendor_version_level : 1;	     /* 1 [29] */
	u32 random_relative_offset : 1;	     /* 1 [30] */
	u32 continuously_increasing : 1;     /* 1 [31] */
#else
	u32 reserved_co2 : 2;		     /* 1 [24-25] */
	u32 e_d_tov_resolution : 1;	     /* 1 [26] */
	u32 alternate_bb_credit_mgmt : 1;    /* 1 [27] */
	u32 nport : 1;			     /* 1 [28] */
	u32 vendor_version_level : 1;	     /* 1 [29] */
	u32 random_relative_offset : 1;	     /* 1 [30] */
	u32 continuously_increasing : 1;     /* 1 [31] */

	u32 payload_length : 1;	     /* 1 [16] */
	u32 seq_cnt : 1;	     /* 1 [17] */
	u32 dynamic_half_duplex : 1; /* 1 [18] */
	u32 reserved_co5 : 5;	     /* 1 [19-23] */

	u32 bb_receive_data_field_size : 12;		   /* 1 [0-11] */
	u32 reserved_co1 : 4;				   /* 1 [12-15] */
#endif

#if defined(UNF_CPU_ENDIAN)
	u32 relative_offset : 16;		   /* 2 [0-15] */
	u32 nport_total_concurrent_sequences : 16; /* 2 [16-31] */
#else
	u32 nport_total_concurrent_sequences : 16;	   /* 2 [16-31] */
	u32 relative_offset : 16;			   /* 2 [0-15] */
#endif

	u32 e_d_tov;
};

/* FC-LS-2 Class Service Parameters Applicability */
struct unf_lgn_port_clparm {
#if defined(UNF_CPU_ENDIAN)
	u32 reserved_cl1 : 6;				 /* 0 [0-5] */
	u32 ic_data_compression_history_buffer_size : 2; /* 0 [6-7] */
	u32 ic_data_compression_capable : 1;		 /* 0 [8] */

	u32 ic_ack_generation_assistance : 1;		   /* 0 [9] */
	u32 ic_ack_n_capable : 1;			   /* 0 [10] */
	u32 ic_ack_o_capable : 1;			   /* 0 [11] */
	u32 ic_initial_responder_processes_accociator : 2; /* 0 [12-13] */
	u32 ic_x_id_reassignment : 2;			   /* 0 [14-15] */

	u32 reserved_cl2 : 7;		 /* 0 [16-22] */
	u32 priority : 1;		 /* 0 [23] */
	u32 buffered_class : 1;		 /* 0 [24] */
	u32 camp_on : 1;		 /* 0 [25] */
	u32 dedicated_simplex : 1;	 /* 0 [26] */
	u32 sequential_delivery : 1;	 /* 0 [27] */
	u32 stacked_connect_request : 2; /* 0 [28-29] */
	u32 intermix_mode : 1;		 /* 0 [30] */
	u32 valid : 1;			 /* 0 [31] */
#else
	u32 buffered_class : 1;				   /* 0 [24] */
	u32 camp_on : 1;				   /* 0 [25] */
	u32 dedicated_simplex : 1;			   /* 0 [26] */
	u32 sequential_delivery : 1;			   /* 0 [27] */
	u32 stacked_connect_request : 2;		   /* 0 [28-29] */
	u32 intermix_mode : 1;				   /* 0 [30] */
	u32 valid : 1;					   /* 0 [31] */
	u32 reserved_cl2 : 7;				   /* 0 [16-22] */
	u32 priority : 1;				   /* 0 [23] */
	u32 ic_data_compression_capable : 1;		   /* 0 [8] */
	u32 ic_ack_generation_assistance : 1;		   /* 0 [9] */
	u32 ic_ack_n_capable : 1;			   /* 0 [10] */
	u32 ic_ack_o_capable : 1;			   /* 0 [11] */
	u32 ic_initial_responder_processes_accociator : 2; /* 0 [12-13] */
	u32 ic_x_id_reassignment : 2;			   /* 0 [14-15] */

	u32 reserved_cl1 : 6;				 /* 0 [0-5] */
	u32 ic_data_compression_history_buffer_size : 2; /* 0 [6-7] */
#endif

#if defined(UNF_CPU_ENDIAN)
	u32 received_data_field_size : 16; /* 1 [0-15] */

	u32 reserved_cl3 : 5;				 /* 1 [16-20] */
	u32 rc_data_compression_history_buffer_size : 2; /* 1 [21-22] */
	u32 rc_data_compression_capable : 1;		 /* 1 [23] */

	u32 rc_data_categories_per_sequence : 2; /* 1 [24-25] */
	u32 reserved_cl4 : 1;			 /* 1 [26] */
	u32 rc_error_policy_supported : 2;	 /* 1 [27-28] */
	u32 rc_x_id_interlock : 1;		 /* 1 [29] */
	u32 rc_ack_n_capable : 1;		 /* 1 [30] */
	u32 rc_ack_o_capable : 1;		 /* 1 [31] */
#else
	u32 rc_data_categories_per_sequence : 2;	 /* 1 [24-25] */
	u32 reserved_cl4 : 1;				 /* 1 [26] */
	u32 rc_error_policy_supported : 2;		 /* 1 [27-28] */
	u32 rc_x_id_interlock : 1;			 /* 1 [29] */
	u32 rc_ack_n_capable : 1;			 /* 1 [30] */
	u32 rc_ack_o_capable : 1;			 /* 1 [31] */

	u32 reserved_cl3 : 5;				 /* 1 [16-20] */
	u32 rc_data_compression_history_buffer_size : 2; /* 1 [21-22] */
	u32 rc_data_compression_capable : 1;		 /* 1 [23] */

	u32 received_data_field_size : 16; /* 1 [0-15] */
#endif

#if defined(UNF_CPU_ENDIAN)
	u32 nport_end_to_end_credit : 15; /* 2 [0-14] */
	u32 reserved_cl5 : 1;		  /* 2 [15] */

	u32 concurrent_sequences : 16; /* 2 [16-31] */
#else
	u32 concurrent_sequences : 16;	   /* 2 [16-31] */

	u32 nport_end_to_end_credit : 15;    /* 2 [0-14] */
	u32 reserved_cl5 : 1;		     /* 2 [15] */
#endif

#if defined(UNF_CPU_ENDIAN)
	u32 reserved_cl6 : 16;		     /* 3 [0-15] */
	u32 open_sequence_per_exchange : 16; /* 3 [16-31] */
#else
	u32 open_sequence_per_exchange : 16; /* 3 [16-31] */
	u32 reserved_cl6 : 16;		     /* 3 [0-15] */
#endif
};

struct unf_fabric_parm {
	struct unf_fabric_coparm co_parms;
	u32 high_port_name;
	u32 low_port_name;
	u32 high_node_name;
	u32 low_node_name;
	struct unf_lgn_port_clparm cl_parms[3];
	u32 reserved_1[4];
	u32 vendor_version_level[4];
};

struct unf_lgn_parm {
	struct lgn_port_coparm co_parms;
	u32 high_port_name;
	u32 low_port_name;
	u32 high_node_name;
	u32 low_node_name;
	struct unf_lgn_port_clparm cl_parms[3];
	u32 reserved_1[4];
	u32 vendor_version_level[4];
};

#define ELS_RJT 0x1
#define ELS_ACC 0x2
#define ELS_PLOGI 0x3
#define ELS_FLOGI 0x4
#define ELS_LOGO 0x5
#define ELS_ECHO 0x10
#define ELS_RRQ 0x12
#define ELS_REC 0x13
#define ELS_PRLI 0x20
#define ELS_PRLO 0x21
#define ELS_TPRLO 0x24
#define ELS_PDISC 0x50
#define ELS_FDISC 0x51
#define ELS_ADISC 0x52
#define ELS_RSCN 0x61 /* registered state change notification */
#define ELS_SCR 0x62  /* state change registration */

#define NS_GIEL 0X0101
#define NS_GA_NXT 0X0100
#define NS_GPN_ID 0x0112 /* get port name by ID */
#define NS_GNN_ID 0x0113 /* get node name by ID */
#define NS_GFF_ID 0x011f /* get FC-4 features by ID */
#define NS_GID_PN 0x0121 /* get ID for port name */
#define NS_GID_NN 0x0131 /* get IDs for node name */
#define NS_GID_FT 0x0171 /* get IDs by FC4 type */
#define NS_GPN_FT 0x0172 /* get port names by FC4 type */
#define NS_GID_PT 0x01a1 /* get IDs by port type */
#define NS_RFT_ID 0x0217 /* reg FC4 type for ID */
#define NS_RPN_ID 0x0212 /* reg port name for ID */
#define NS_RNN_ID 0x0213 /* reg node name for ID */
#define NS_RSNPN 0x0218	 /* reg symbolic port name */
#define NS_RFF_ID 0x021f /* reg FC4 Features for ID */
#define NS_RSNN 0x0239	 /* reg symbolic node name */
#define ST_NULL 0xffff	 /* reg symbolic node name */

#define BLS_ABTS 0xA001 /* ABTS */

#define FCP_SRR 0x14		    /* Sequence Retransmission Request */
#define UNF_FC_FID_DOM_MGR 0xfffc00 /* domain manager base */
enum unf_fc_well_known_fabric_id {
	UNF_FC_FID_NONE = 0x000000,	 /* No destination */
	UNF_FC_FID_DOM_CTRL = 0xfffc01,	 /* domain controller */
	UNF_FC_FID_BCAST = 0xffffff,	 /* broadcast */
	UNF_FC_FID_FLOGI = 0xfffffe,	 /* fabric login */
	UNF_FC_FID_FCTRL = 0xfffffd,	 /* fabric controller */
	UNF_FC_FID_DIR_SERV = 0xfffffc,	 /* directory server */
	UNF_FC_FID_TIME_SERV = 0xfffffb, /* time server */
	UNF_FC_FID_MGMT_SERV = 0xfffffa, /* management server */
	UNF_FC_FID_QOS = 0xfffff9,	 /* QoS Facilitator */
	UNF_FC_FID_ALIASES = 0xfffff8,	 /* alias server (FC-PH2) */
	UNF_FC_FID_SEC_KEY = 0xfffff7,	 /* Security key dist. server */
	UNF_FC_FID_CLOCK = 0xfffff6,	 /* clock synch server */
	UNF_FC_FID_MCAST_SERV = 0xfffff5 /* multicast server */
};

#define INVALID_WORLD_ID 0xfffffffc

struct unf_host_param {
	int can_queue;
	u16 sg_table_size;
	short cmnd_per_lun;
	u32 max_id;
	u32 max_lun;
	u32 max_channel;
	u16 max_cmnd_len;
	u16 max_sectors;
	u64 dma_boundary;
	u32 port_id;
	void *lport;
	struct device *pdev;
};

int unf_alloc_scsi_host(struct Scsi_Host **unf_scsi_host, struct unf_host_param *host_param);
void unf_free_scsi_host(struct Scsi_Host *unf_scsi_host);
u32 unf_register_ini_transport(void);
void unf_unregister_ini_transport(void);
void unf_save_sense_data(void *scsi_cmd, const char *sense, int sens_len);

#endif
