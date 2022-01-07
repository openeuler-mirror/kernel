/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef __SPRAID_H_
#define __SPRAID_H_

#define SPRAID_CAP_MQES(cap) ((cap) & 0xffff)
#define SPRAID_CAP_STRIDE(cap) (((cap) >> 32) & 0xf)
#define SPRAID_CAP_MPSMIN(cap) (((cap) >> 48) & 0xf)
#define SPRAID_CAP_MPSMAX(cap) (((cap) >> 52) & 0xf)
#define SPRAID_CAP_TIMEOUT(cap) (((cap) >> 24) & 0xff)
#define SPRAID_CAP_DMAMASK(cap) (((cap) >> 37) & 0xff)

#define SPRAID_DEFAULT_MAX_CHANNEL 4
#define SPRAID_DEFAULT_MAX_ID 240
#define SPRAID_DEFAULT_MAX_LUN_PER_HOST 8
#define MAX_SECTORS 2048

#define IO_SQE_SIZE sizeof(struct spraid_ioq_command)
#define ADMIN_SQE_SIZE sizeof(struct spraid_admin_command)
#define SQE_SIZE(qid) (((qid) > 0) ? IO_SQE_SIZE : ADMIN_SQE_SIZE)
#define CQ_SIZE(depth) ((depth) * sizeof(struct spraid_completion))
#define SQ_SIZE(qid, depth) ((depth) * SQE_SIZE(qid))

#define SENSE_SIZE(depth)	((depth) * SCSI_SENSE_BUFFERSIZE)

#define SPRAID_AQ_DEPTH 128
#define SPRAID_NR_AEN_COMMANDS 16
#define SPRAID_AQ_BLK_MQ_DEPTH (SPRAID_AQ_DEPTH - SPRAID_NR_AEN_COMMANDS)
#define SPRAID_AQ_MQ_TAG_DEPTH (SPRAID_AQ_BLK_MQ_DEPTH - 1)

#define SPRAID_ADMIN_QUEUE_NUM 1
#define SPRAID_PTCMDS_PERQ 1
#define SPRAID_IO_BLK_MQ_DEPTH (hdev->shost->can_queue)
#define SPRAID_NR_IOQ_PTCMDS (SPRAID_PTCMDS_PERQ * hdev->shost->nr_hw_queues)

#define FUA_MASK 0x08
#define SPRAID_MINORS BIT(MINORBITS)

#define COMMAND_IS_WRITE(cmd) ((cmd)->common.opcode & 1)

#define SPRAID_IO_IOSQES 7
#define SPRAID_IO_IOCQES 4
#define PRP_ENTRY_SIZE 8

#define SMALL_POOL_SIZE 256
#define MAX_SMALL_POOL_NUM 16
#define MAX_CMD_PER_DEV 64
#define MAX_CDB_LEN 32

#define SPRAID_UP_TO_MULTY4(x) (((x) + 4) & (~0x03))

#define CQE_STATUS_SUCCESS (0x0)

#define PCI_VENDOR_ID_RAMAXEL_LOGIC 0x1E81

#define SPRAID_SERVER_DEVICE_HBA_DID		0x2100
#define SPRAID_SERVER_DEVICE_RAID_DID		0x2200

#define IO_6_DEFAULT_TX_LEN 256

#define SPRAID_INT_PAGES 2
#define SPRAID_INT_BYTES(hdev) (SPRAID_INT_PAGES * (hdev)->page_size)

enum {
	SPRAID_REQ_CANCELLED = (1 << 0),
	SPRAID_REQ_USERCMD = (1 << 1),
};

enum {
	SPRAID_SC_SUCCESS = 0x0,
	SPRAID_SC_INVALID_OPCODE = 0x1,
	SPRAID_SC_INVALID_FIELD  = 0x2,

	SPRAID_SC_ABORT_LIMIT = 0x103,
	SPRAID_SC_ABORT_MISSING = 0x104,
	SPRAID_SC_ASYNC_LIMIT = 0x105,

	SPRAID_SC_DNR = 0x4000,
};

enum {
	SPRAID_REG_CAP  = 0x0000,
	SPRAID_REG_CC   = 0x0014,
	SPRAID_REG_CSTS = 0x001c,
	SPRAID_REG_AQA  = 0x0024,
	SPRAID_REG_ASQ  = 0x0028,
	SPRAID_REG_ACQ  = 0x0030,
	SPRAID_REG_DBS  = 0x1000,
};

enum {
	SPRAID_CC_ENABLE     = 1 << 0,
	SPRAID_CC_CSS_NVM    = 0 << 4,
	SPRAID_CC_MPS_SHIFT  = 7,
	SPRAID_CC_AMS_SHIFT  = 11,
	SPRAID_CC_SHN_SHIFT  = 14,
	SPRAID_CC_IOSQES_SHIFT = 16,
	SPRAID_CC_IOCQES_SHIFT = 20,
	SPRAID_CC_AMS_RR       = 0 << SPRAID_CC_AMS_SHIFT,
	SPRAID_CC_SHN_NONE     = 0 << SPRAID_CC_SHN_SHIFT,
	SPRAID_CC_IOSQES       = SPRAID_IO_IOSQES << SPRAID_CC_IOSQES_SHIFT,
	SPRAID_CC_IOCQES       = SPRAID_IO_IOCQES << SPRAID_CC_IOCQES_SHIFT,
	SPRAID_CC_SHN_NORMAL   = 1 << SPRAID_CC_SHN_SHIFT,
	SPRAID_CC_SHN_MASK     = 3 << SPRAID_CC_SHN_SHIFT,
	SPRAID_CSTS_CFS_SHIFT  = 1,
	SPRAID_CSTS_SHST_SHIFT = 2,
	SPRAID_CSTS_PP_SHIFT   = 5,
	SPRAID_CSTS_RDY	       = 1 << 0,
	SPRAID_CSTS_SHST_CMPLT = 2 << 2,
	SPRAID_CSTS_SHST_MASK  = 3 << 2,
	SPRAID_CSTS_CFS_MASK   = 1 << SPRAID_CSTS_CFS_SHIFT,
	SPRAID_CSTS_PP_MASK    = 1 << SPRAID_CSTS_PP_SHIFT,
};

enum {
	SPRAID_ADMIN_DELETE_SQ = 0x00,
	SPRAID_ADMIN_CREATE_SQ = 0x01,
	SPRAID_ADMIN_DELETE_CQ = 0x04,
	SPRAID_ADMIN_CREATE_CQ = 0x05,
	SPRAID_ADMIN_ABORT_CMD = 0x08,
	SPRAID_ADMIN_SET_FEATURES = 0x09,
	SPRAID_ADMIN_ASYNC_EVENT = 0x0c,
	SPRAID_ADMIN_GET_INFO = 0xc6,
	SPRAID_ADMIN_RESET = 0xc8,
};

enum {
	SPRAID_GET_INFO_CTRL = 0,
	SPRAID_GET_INFO_DEV_LIST = 1,
};

enum {
	SPRAID_RESET_TARGET = 0,
	SPRAID_RESET_BUS = 1,
};

enum {
	SPRAID_AEN_ERROR = 0,
	SPRAID_AEN_NOTICE = 2,
	SPRAID_AEN_VS = 7,
};

enum {
	SPRAID_AEN_DEV_CHANGED = 0x00,
	SPRAID_AEN_FW_ACT_START = 0x01,
	SPRAID_AEN_HOST_PROBING = 0x10,
};

enum {
	SPRAID_AEN_TIMESYN = 0x00,
	SPRAID_AEN_FW_ACT_FINISH = 0x02,
	SPRAID_AEN_EVENT_MIN = 0x80,
	SPRAID_AEN_EVENT_MAX = 0xff,
};

enum {
	SPRAID_CMD_WRITE = 0x01,
	SPRAID_CMD_READ = 0x02,

	SPRAID_CMD_NONIO_NONE = 0x80,
	SPRAID_CMD_NONIO_TODEV = 0x81,
	SPRAID_CMD_NONIO_FROMDEV = 0x82,
};

enum {
	SPRAID_QUEUE_PHYS_CONTIG = (1 << 0),
	SPRAID_CQ_IRQ_ENABLED = (1 << 1),

	SPRAID_FEAT_NUM_QUEUES = 0x07,
	SPRAID_FEAT_ASYNC_EVENT = 0x0b,
	SPRAID_FEAT_TIMESTAMP = 0x0e,
};

enum spraid_state {
	SPRAID_NEW,
	SPRAID_LIVE,
	SPRAID_RESETTING,
	SPRAID_DELETING,
	SPRAID_DEAD,
};

enum {
	SPRAID_CARD_HBA,
	SPRAID_CARD_RAID,
};

enum spraid_cmd_type {
	SPRAID_CMD_ADM,
	SPRAID_CMD_IOPT,
};

struct spraid_completion {
	__le32 result;
	union {
		struct {
			__u8	sense_len;
			__u8	resv[3];
		};
		__le32	result1;
	};
	__le16 sq_head;
	__le16 sq_id;
	__u16  cmd_id;
	__le16 status;
};

struct spraid_ctrl_info {
	__le32 nd;
	__le16 max_cmds;
	__le16 max_channel;
	__le32 max_tgt_id;
	__le16 max_lun;
	__le16 max_num_sge;
	__le16 lun_num_in_boot;
	__u8   mdts;
	__u8   acl;
	__u8   aerl;
	__u8   card_type;
	__u16  rsvd;
	__u32  rtd3e;
	__u8   sn[32];
	__u8   fr[16];
	__u8   rsvd1[4020];
};

struct spraid_dev {
	struct pci_dev *pdev;
	struct device *dev;
	struct Scsi_Host *shost;
	struct spraid_queue *queues;
	struct dma_pool *prp_page_pool;
	struct dma_pool *prp_small_pool[MAX_SMALL_POOL_NUM];
	mempool_t *iod_mempool;
	void __iomem *bar;
	u32 max_qid;
	u32 num_vecs;
	u32 queue_count;
	u32 ioq_depth;
	int db_stride;
	u32 __iomem *dbs;
	struct rw_semaphore devices_rwsem;
	int numa_node;
	u32 page_size;
	u32 ctrl_config;
	u32 online_queues;
	u64 cap;
	int instance;
	struct spraid_ctrl_info *ctrl_info;
	struct spraid_dev_info *devices;

	struct spraid_cmd *adm_cmds;
	struct list_head adm_cmd_list;
	spinlock_t adm_cmd_lock;

	struct spraid_cmd *ioq_ptcmds;
	struct list_head ioq_pt_list;
	spinlock_t ioq_pt_lock;

	struct work_struct scan_work;
	struct work_struct timesyn_work;
	struct work_struct reset_work;
	struct work_struct fw_act_work;

	enum spraid_state state;
	spinlock_t state_lock;

	struct request_queue *bsg_queue;
};

struct spraid_sgl_desc {
	__le64 addr;
	__le32 length;
	__u8   rsvd[3];
	__u8   type;
};

union spraid_data_ptr {
	struct {
		__le64 prp1;
		__le64 prp2;
	};
	struct spraid_sgl_desc sgl;
};

struct spraid_admin_common_command {
	__u8	opcode;
	__u8	flags;
	__u16	command_id;
	__le32	hdid;
	__le32	cdw2[4];
	union spraid_data_ptr	dptr;
	__le32	cdw10;
	__le32	cdw11;
	__le32	cdw12;
	__le32	cdw13;
	__le32	cdw14;
	__le32	cdw15;
};

struct spraid_features {
	__u8	opcode;
	__u8	flags;
	__u16	command_id;
	__le32	hdid;
	__u64	rsvd2[2];
	union spraid_data_ptr dptr;
	__le32	fid;
	__le32	dword11;
	__le32	dword12;
	__le32	dword13;
	__le32	dword14;
	__le32	dword15;
};

struct spraid_create_cq {
	__u8	opcode;
	__u8	flags;
	__u16	command_id;
	__u32	rsvd1[5];
	__le64	prp1;
	__u64	rsvd8;
	__le16	cqid;
	__le16	qsize;
	__le16	cq_flags;
	__le16	irq_vector;
	__u32	rsvd12[4];
};

struct spraid_create_sq {
	__u8	opcode;
	__u8	flags;
	__u16	command_id;
	__u32	rsvd1[5];
	__le64	prp1;
	__u64	rsvd8;
	__le16	sqid;
	__le16	qsize;
	__le16	sq_flags;
	__le16	cqid;
	__u32	rsvd12[4];
};

struct spraid_delete_queue {
	__u8	opcode;
	__u8	flags;
	__u16	command_id;
	__u32	rsvd1[9];
	__le16	qid;
	__u16	rsvd10;
	__u32	rsvd11[5];
};

struct spraid_get_info {
	__u8	opcode;
	__u8	flags;
	__u16	command_id;
	__le32	hdid;
	__u32	rsvd2[4];
	union spraid_data_ptr	dptr;
	__u8	type;
	__u8	rsvd10[3];
	__le32	cdw11;
	__u32	rsvd12[4];
};

struct spraid_usr_cmd {
	__u8	opcode;
	__u8	flags;
	__u16	command_id;
	__le32	hdid;
	union {
		struct {
			__le16 subopcode;
			__le16 rsvd1;
		} info_0;
		__le32 cdw2;
	};
	union {
		struct {
			__le16 data_len;
			__le16 param_len;
		} info_1;
		__le32 cdw3;
	};
	__u64 metadata;
	union spraid_data_ptr	dptr;
	__le32 cdw10;
	__le32 cdw11;
	__le32 cdw12;
	__le32 cdw13;
	__le32 cdw14;
	__le32 cdw15;
};

enum {
	SPRAID_CMD_FLAG_SGL_METABUF = (1 << 6),
	SPRAID_CMD_FLAG_SGL_METASEG = (1 << 7),
	SPRAID_CMD_FLAG_SGL_ALL     = SPRAID_CMD_FLAG_SGL_METABUF | SPRAID_CMD_FLAG_SGL_METASEG,
};

enum spraid_cmd_state {
	SPRAID_CMD_IDLE = 0,
	SPRAID_CMD_IN_FLIGHT = 1,
	SPRAID_CMD_COMPLETE = 2,
	SPRAID_CMD_TIMEOUT = 3,
	SPRAID_CMD_TMO_COMPLETE = 4,
};

struct spraid_abort_cmd {
	__u8	opcode;
	__u8	flags;
	__u16	command_id;
	__le32	hdid;
	__u64	rsvd2[4];
	__le16	sqid;
	__le16	cid;
	__u32	rsvd11[5];
};

struct spraid_reset_cmd {
	__u8	opcode;
	__u8	flags;
	__u16	command_id;
	__le32	hdid;
	__u64	rsvd2[4];
	__u8	type;
	__u8	rsvd10[3];
	__u32	rsvd11[5];
};

struct spraid_admin_command {
	union {
		struct spraid_admin_common_command common;
		struct spraid_features features;
		struct spraid_create_cq create_cq;
		struct spraid_create_sq create_sq;
		struct spraid_delete_queue delete_queue;
		struct spraid_get_info get_info;
		struct spraid_abort_cmd abort;
		struct spraid_reset_cmd reset;
		struct spraid_usr_cmd usr_cmd;
	};
};

struct spraid_ioq_common_command {
	__u8	opcode;
	__u8	flags;
	__u16	command_id;
	__le32	hdid;
	__le16	sense_len;
	__u8	cdb_len;
	__u8	rsvd2;
	__le32	cdw3[3];
	union spraid_data_ptr	dptr;
	__le32	cdw10[6];
	__u8	cdb[32];
	__le64	sense_addr;
	__le32	cdw26[6];
};

struct spraid_rw_command {
	__u8	opcode;
	__u8	flags;
	__u16	command_id;
	__le32	hdid;
	__le16	sense_len;
	__u8	cdb_len;
	__u8	rsvd2;
	__u32	rsvd3[3];
	union spraid_data_ptr	dptr;
	__le64	slba;
	__le16	nlb;
	__le16	control;
	__u32	rsvd13[3];
	__u8	cdb[32];
	__le64	sense_addr;
	__u32	rsvd26[6];
};

struct spraid_scsi_nonio {
	__u8	opcode;
	__u8	flags;
	__u16	command_id;
	__le32	hdid;
	__le16	sense_len;
	__u8	cdb_length;
	__u8	rsvd2;
	__u32	rsvd3[3];
	union spraid_data_ptr	dptr;
	__u32	rsvd10[5];
	__le32	buffer_len;
	__u8	cdb[32];
	__le64	sense_addr;
	__u32	rsvd26[6];
};

struct spraid_ioq_command {
	union {
		struct spraid_ioq_common_command common;
		struct spraid_rw_command rw;
		struct spraid_scsi_nonio scsi_nonio;
	};
};

struct spraid_passthru_common_cmd {
	__u8	opcode;
	__u8	flags;
	__u16	rsvd0;
	__u32	nsid;
	union {
		struct {
			__u16 subopcode;
			__u16 rsvd1;
		} info_0;
		__u32 cdw2;
	};
	union {
		struct {
			__u16 data_len;
			__u16 param_len;
		} info_1;
		__u32 cdw3;
	};
	__u64 metadata;

	__u64 addr;
	__u64 prp2;

	__u32 cdw10;
	__u32 cdw11;
	__u32 cdw12;
	__u32 cdw13;
	__u32 cdw14;
	__u32 cdw15;
	__u32 timeout_ms;
	__u32 result0;
	__u32 result1;
};

struct spraid_ioq_passthru_cmd {
	__u8  opcode;
	__u8  flags;
	__u16 rsvd0;
	__u32 nsid;
	union {
		struct {
			__u16 res_sense_len;
			__u8  cdb_len;
			__u8  rsvd0;
		} info_0;
		__u32 cdw2;
	};
	union {
		struct {
			__u16 subopcode;
			__u16 rsvd1;
		} info_1;
		__u32 cdw3;
	};
	union {
		struct {
			__u16 rsvd;
			__u16 param_len;
		} info_2;
		__u32 cdw4;
	};
	__u32 cdw5;
	__u64 addr;
	__u64 prp2;
	union {
		struct {
			__u16 eid;
			__u16 sid;
		} info_3;
		__u32 cdw10;
	};
	union {
		struct {
			__u16 did;
			__u8  did_flag;
			__u8  rsvd2;
		} info_4;
		__u32 cdw11;
	};
	__u32 cdw12;
	__u32 cdw13;
	__u32 cdw14;
	__u32 data_len;
	__u32 cdw16;
	__u32 cdw17;
	__u32 cdw18;
	__u32 cdw19;
	__u32 cdw20;
	__u32 cdw21;
	__u32 cdw22;
	__u32 cdw23;
	__u64 sense_addr;
	__u32 cdw26[4];
	__u32 timeout_ms;
	__u32 result0;
	__u32 result1;
};

struct spraid_bsg_request {
	u32  msgcode;
	u32 control;
	union {
		struct spraid_passthru_common_cmd admcmd;
		struct spraid_ioq_passthru_cmd    ioqcmd;
	};
};

enum {
	SPRAID_BSG_ADM,
	SPRAID_BSG_IOQ,
};

struct spraid_cmd {
	int qid;
	int cid;
	u32 result0;
	u32 result1;
	u16 status;
	void *priv;
	enum spraid_cmd_state state;
	struct completion cmd_done;
	struct list_head list;
};

struct spraid_queue {
	struct spraid_dev *hdev;
	spinlock_t sq_lock; /* spinlock for lock handling */

	spinlock_t cq_lock ____cacheline_aligned_in_smp; /* spinlock for lock handling */

	void *sq_cmds;

	struct spraid_completion *cqes;

	dma_addr_t sq_dma_addr;
	dma_addr_t cq_dma_addr;
	u32 __iomem *q_db;
	u8 cq_phase;
	u8 sqes;
	u16 qid;
	u16 sq_tail;
	u16 cq_head;
	u16 last_cq_head;
	u16 q_depth;
	s16 cq_vector;
	void *sense;
	dma_addr_t sense_dma_addr;
	struct dma_pool *prp_small_pool;
};

struct spraid_iod {
	struct spraid_queue *spraidq;
	enum spraid_cmd_state state;
	int npages;
	u32 nsge;
	u32 length;
	bool use_sgl;
	bool sg_drv_mgmt;
	dma_addr_t first_dma;
	void *sense;
	dma_addr_t sense_dma;
	struct scatterlist *sg;
	struct scatterlist inline_sg[0];
};

#define SPRAID_DEV_INFO_ATTR_BOOT(attr) ((attr) & 0x01)
#define SPRAID_DEV_INFO_ATTR_VD(attr) (((attr) & 0x02) == 0x0)
#define SPRAID_DEV_INFO_ATTR_PT(attr) (((attr) & 0x22) == 0x02)
#define SPRAID_DEV_INFO_ATTR_RAWDISK(attr) ((attr) & 0x20)

#define SPRAID_DEV_INFO_FLAG_VALID(flag) ((flag) & 0x01)
#define SPRAID_DEV_INFO_FLAG_CHANGE(flag) ((flag) & 0x02)

#define BGTASK_TYPE_REBUILD 4
#define USR_CMD_READ 0xc2
#define USR_CMD_RDLEN 0x1000
#define USR_CMD_VDINFO 0x704
#define USR_CMD_BGTASK 0x504
#define VDINFO_PARAM_LEN 0x04

struct spraid_vd_info {
	__u8 name[32];
	__le16 id;
	__u8 rg_id;
	__u8 rg_level;
	__u8 sg_num;
	__u8 sg_disk_num;
	__u8 vd_status;
	__u8 vd_type;
	__u8 rsvd1[4056];
};

#define MAX_REALTIME_BGTASK_NUM 32

struct bgtask_info {
	__u8 type;
	__u8 progress;
	__u8 rate;
	__u8 rsvd0;
	__le16 vd_id;
	__le16 time_left;
	__u8 rsvd1[4];
};

struct spraid_bgtask {
	__u8 sw;
	__u8 task_num;
	__u8 rsvd[6];
	struct bgtask_info bgtask[MAX_REALTIME_BGTASK_NUM];
};

struct spraid_dev_info {
	__le32	hdid;
	__le16	target;
	__u8	channel;
	__u8	lun;
	__u8	attr;
	__u8	flag;
	__le16	max_io_kb;
};

#define MAX_DEV_ENTRY_PER_PAGE_4K	340
struct spraid_dev_list {
	__le32	dev_num;
	__u32	rsvd0[3];
	struct spraid_dev_info	devices[MAX_DEV_ENTRY_PER_PAGE_4K];
};

struct spraid_sdev_hostdata {
	u32 hdid;
	u16 max_io_kb;
	u8 attr;
	u8 flag;
	u8 rg_id;
	u8 rsvd[3];
};

#endif

