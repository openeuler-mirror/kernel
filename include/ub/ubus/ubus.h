/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#ifndef _UB_UBUS_UBUS_H_
#define _UB_UBUS_UBUS_H_

#include <linux/kabi.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/iommu.h>
#include <linux/ioport.h>
#include <linux/types.h>
#include <uapi/ub/ubus/ubus.h>
#include <uapi/ub/ubus/ubus_regs.h>
#include <ub/ubus/ubus_ids.h>
#include <linux/mod_devicetable.h>

#define UB_ENTITY(v, d) \
	.vendor = (v), .device = (d), \
	.mod_vendor = (u32)UB_ANY_ID, .module = (u32)UB_ANY_ID

#define UB_ENTITY_DRIVER_OVERRIDE(v, d, driver_override) \
	.vendor = (v), .device = (d), \
	.mod_vendor = (u32)UB_ANY_ID, .module = (u32)UB_ANY_ID, \
	.override_only = (driver_override)

#define UB_DRIVER_OVERRIDE_ENTITY_VFIO(v, d) \
	UB_ENTITY_DRIVER_OVERRIDE(v, d, UB_ID_F_VFIO_DRIVER_OVERRIDE)

#define UB_ENTITY_MODULE(v, d, m_v, m) \
	.vendor = (v), .device = (d), \
	.mod_vendor = (m_v), .module = (m)

#define UB_ENTITY_CLASS(dev_class, dev_class_mask) \
	.vendor = (u32)UB_ANY_ID, .device = (u32)UB_ANY_ID, \
	.mod_vendor = (u32)UB_ANY_ID, .module = (u32)UB_ANY_ID, \
	.class_code = (dev_class), .class_mask = (dev_class_mask)

#define ub_resource_start(dev, resno)	((dev)->zone[(resno)].res.start)
#define ub_resource_end(dev, resno)	((dev)->zone[(resno)].res.end)
#define ub_resource_flags(dev, resno)	((dev)->zone[(resno)].res.flags)
#define ub_resource_len(dev, resno) \
	((ub_resource_start((dev), (resno)) == 0 &&	\
	  ub_resource_end((dev), (resno)) ==		\
	  ub_resource_start((dev), (resno))) ? 0 :	\
	(ub_resource_end((dev), (resno)) -		\
	ub_resource_start((dev), (resno)) + 1))

typedef unsigned int __bitwise ub_channel_state_t;
enum {
	ub_channel_io_normal = (__force ub_channel_state_t) 1,
	ub_channel_io_frozen = (__force ub_channel_state_t) 2,
	ub_channel_io_perm_failure = (__force ub_channel_state_t) 3,
};

typedef unsigned int __bitwise ub_ers_result_t;
enum ub_ers_result {
	UB_ERS_RESULT_NONE = (__force ub_ers_result_t) 1,
	UB_ERS_RESULT_CAN_RECOVER = (__force ub_ers_result_t) 2,
	UB_ERS_RESULT_NEED_RESET = (__force ub_ers_result_t) 3,
	UB_ERS_RESULT_DISCONNECT = (__force ub_ers_result_t) 4,
	UB_ERS_RESULT_RECOVERED = (__force ub_ers_result_t) 5,
	UB_ERS_RESULT_NO_ERR_DRIVER = (__force ub_ers_result_t) 6,
};

#define UB_GUID_DW_NUM SZ_4

struct ub_bus_region {
	unsigned long start;
	unsigned long size;
};

struct mmio_zone {
	struct resource res;
	struct ub_bus_region region;
	u8 ubba_used;
	u8 sa_used;
	u8 init_succ;
	u8 decoder_mapped;
};

struct ub_guid {
	union {
		struct {
			unsigned long long seq_num;
			unsigned int reserved : 24;
			unsigned int type : 4;
			unsigned int version : 4;
			unsigned int device : 16;
			unsigned int vendor : 16;
		} bits;

		guid_t id;

		unsigned int dw[UB_GUID_DW_NUM];
	};
};

#define uent_vendor(uent) ((uent)->guid.bits.vendor)
#define uent_type(uent) ((uent)->guid.bits.type)
#define uent_version(uent) ((uent)->guid.bits.version)
#define uent_device(uent) ((uent)->guid.bits.device)
#define uent_class(uent) ((uent)->class_code)
#define uent_base_code(uent) ((uent)->class_code & UB_BASE_CODE_MASK)
#define uent_seq(uent) ((uent)->guid.bits.seq_num)

enum ub_type {
	UB_TYPE_BUS_INSTANCE = 0,
	UB_TYPE_CONTROLLER = 1,
	UB_TYPE_ICONTROLLER = 2,
	UB_TYPE_SWITCH = 3,
	UB_TYPE_ISWITCH = 4
};

static inline int ub_show_guid(struct ub_guid *guid, char *buf)
{
	return sprintf(buf, "%04x-%04x-%01x-%01x-%06x-%016llx",
		       guid->bits.vendor, guid->bits.device,
		       guid->bits.version, guid->bits.type,
		       guid->bits.reserved, guid->bits.seq_num);
}

#define MAX_UB_RES_NUM 3

enum ub_port_type {
	PHYSICAL,
	VIRTUAL,
};

#define UB_MAX_CNA_NUM SZ_64K
#define UB_PORT_CAP_NUM SZ_256

enum ub_link_state {
	LINK_STATE_NORMAL = 0,
	LINK_STATE_RESETING = 1,
	LINK_STATE_DONE = 2,
};

struct ub_port {
	struct ub_entity *uent;
	u16 index;
	enum ub_port_type type;
	u8 domain_boundary;
	bool shareable;
	u32 cna;
	struct ub_entity *r_uent; /* If valid, also represent link up */
	u16 r_index;
	guid_t r_guid;
	struct kobject kobj;
	DECLARE_BITMAP(cna_maps, UB_MAX_CNA_NUM);
	/* hotplug info */
	struct ub_slot *slot;
	/* cap cache */
	DECLARE_BITMAP(cap_map, UB_PORT_CAP_NUM);

	struct work_struct link_work;
	enum ub_link_state link_state;
	u8 link_event;

#ifndef __GENKSYMS__
	union {
		struct {
			atomic_t port_mgmt_state;
		};
		u64 reserved1;
	};
#else
	KABI_RESERVE(1)
#endif

#ifndef __GENKSYMS__
	struct mutex *port_lock;
#else
	KABI_RESERVE(2)
#endif
};

struct ue_map {
	u16 start_entity_idx;
	u16 end_entity_idx;
};

struct ub_entity {
	/* Driver framework base info */
	struct device dev;
	struct ub_driver *driver;
	bool match_driver; /* Skip attaching driver before dev ready */
	const char *driver_override; /* Driver name to force a match */
	unsigned long priv_flags; /* Private flags for the UB driver */

	/* entity base info */
	bool pool;
	int ent_type;
	struct ub_guid guid;
	u16 class_code;
	u16 mod_vendor; /* entity's module vendor and module id */
	u16 module;
	unsigned int cna;
	unsigned int eid;
	unsigned short entity_idx;
	u32 uent_num; /* ub dev number */
	u32 fm_cna;
	struct mmio_zone zone[MAX_UB_RES_NUM];
	unsigned int total_funcs;
	u32 token_id;
	u32 token_value;

	/* MUE & UE info */
	u8 is_mue;
	u16 total_ues;
	u16 num_ues;
	struct ue_map uem;
	struct list_head mue_list; /* management ub entity list */
	struct list_head ue_list; /* entity list in management ub entity */
	u8 is_vdm_idev;

	/* entity topology info */
	struct list_head node;
	struct ub_bus_controller *ubc;
	struct ub_entity *pue; /* UE/MUE connected to their MUE */
	int topo_rank; /* The levels of Breadth-First Search */

	/* entity port info */
	u16 port_nums;
	struct ub_port *ports;

	/* entity capability info */
	unsigned int cfg0_bitmap[8];
	unsigned int cfg1_bitmap[8];

	unsigned int state_saved : 1;

	/* entity DMA info */
	u64 dma_mask;
	struct device_dma_parameters dma_parms;

	/* entity user interface */
	struct bin_attribute *res_attr[MAX_UB_RES_NUM]; /* sysfs file for resources */
	/* sysfs file for WC mapping of resources */
	struct bin_attribute *res_attr_wc[MAX_UB_RES_NUM];

	/* UB interrupt info */
	raw_spinlock_t usi_lock;
	unsigned int no_intr : 1;
	unsigned int intr_enabled : 1;
	unsigned int intr_type1 : 1;
	void __iomem *intr_addr_base;
	void __iomem *intr_vector_base;
	u32 intr_device_id;
	const struct attribute_group **msi_irq_groups;

	/* UB reset info */
	unsigned int reset_fn : 1;

	/* entity route info */
	struct list_head cna_list; /* store distance for cna in route table */

	/* entity slot info */
	struct list_head slot_list; /* store slots under this dev */

	struct dev_message *message;

	/* UB entity TID */
	u32 tid;

	bool sw_cap;

	/* UB saved config space */
	u32 saved_config_space[24]; /* Config space saved at reset time */

	/* entity bus instance info */
	struct mutex instance_lock;
	struct list_head instance_node;
	struct ub_bus_instance *bi;
	u32 user_eid;
	struct ub_eu_table *eu_table;

	struct mutex active_mutex;

	u32 support_feature;

	u16 upi;

#ifndef __GENKSYMS__
	union {
		struct {
			atomic_t ent_mgmt_state;
			u32 task_src;
		};
		u64 reserved1;
	};
#else
	KABI_RESERVE(1)
#endif
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
	KABI_RESERVE(5)
	KABI_RESERVE(6)
	KABI_RESERVE(7)
	KABI_RESERVE(8)
	KABI_RESERVE(9)
	KABI_RESERVE(10)
	KABI_RESERVE(11)
	KABI_RESERVE(12)
	KABI_RESERVE(13)
	KABI_RESERVE(14)
	KABI_RESERVE(15)
	KABI_RESERVE(16)
};

/* UB bus error event callbacks */
struct ub_error_handlers {
	/* UB function reset prepare or completed */

	/*
	 * Deprecated: This function is going to be removed in future version.
	 * Please use ub_reset_prepare_return() and ub_reset_done_with_pret()
	 * instead, which provides more complete return value processing.
	 */
	void (*ub_reset_prepare)(struct ub_entity *uent);
	void (*ub_reset_done)(struct ub_entity *uent);
	ub_ers_result_t (*ub_error_detected)(struct ub_entity *uent, ub_channel_state_t state);
	ub_ers_result_t (*ub_resource_enabled)(struct ub_entity *uent);

#ifndef __GENKSYMS__
	int (*ub_reset_prepare_return)(struct ub_entity *uent);
	int (*ub_reset_done_with_pret)(struct ub_entity *uent, int pret);
#else
	KABI_RESERVE(1)
	KABI_RESERVE(2)
#endif
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

struct ub_dynids {
	spinlock_t lock; /* Protects list, index */
	struct list_head list; /* For IDs added at runtime */
};

#define to_ub_entity(n) container_of(n, struct ub_entity, dev)

/**
 * struct ub_driver - UB driver structure
 * @node:	List of driver structures.
 * @name:	Driver name.
 * @id_table:	Pointer to table of device IDs the driver is
 *		interested in.  Most drivers should export this
 *		table using MODULE_DEVICE_TABLE(ub,...).
 * @probe:	This probing function gets called (during execution
 *		of ub_register_driver() for already existing
 *		entities or later if a new entity gets inserted) for
 *		all UB entities which match the ID table and are not
 *		"owned" by the other drivers yet. This function gets
 *		passed a "struct ub_entity *" for each entity whose
 *		entry in the ID table matches the entity. The probe
 *		function returns zero when the driver chooses to
 *		take "ownership" of the entity or an error code
 *		(negative number) otherwise.
 *		The probe function always gets called from process
 *		context, so it can sleep.
 * @remove:	The remove() function gets called whenever an entity
 *		being handled by this driver is removed (either during
 *		deregistration of the driver or when it's manually
 *		removed from a hot-pluggable slot).
 *		The remove function always gets called from process
 *		context, so it can sleep.
 * @shutdown:	Hook into reboot_notifier_list (kernel/sys.c).
 *		Intended to stop any idling operations.
 * @virt_configure: Optional driver callback to allow configuration of
 *		UEs. This function is called to enable or disable UEs.
 * @virt_notify: Optional driver callback to notify the driver about
 *		changes in UE status. This function is called
 *		when the status of a UE changes.
 * @activate:	Activate a specific entity. This function is called to
 *		activate an entity by its index.
 * @deactivate:	Deactivate a specific entity. This function is called to
 *		deactivate an entity by its index.
 * @err_handler: Error handling callbacks.
 * @groups:	Sysfs attribute groups.
 * @dev_groups: Attributes attached to the device that will be
 *		created once it is bound to the driver.
 * @driver:	Driver model structure.
 * @dynids:	List of dynamically added device IDs.
 * @driver_managed_dma: Device driver doesn't use kernel DMA API for DMA.
 *		For most device drivers, no need to care about this flag
 *		as long as all DMAs are handled through the kernel DMA API.
 *		For some special ones, for example VFIO drivers, they know
 *		how to manage the DMA themselves and set this flag so that
 *		the IOMMU layer will allow them to setup and manage their
 *		own I/O address space.
 */
struct ub_driver {
	struct list_head node;
	const char *name;
	const struct ub_device_id *id_table; /* Must be non-NULL for probe to be called */
	/* New entity inserted */
	int (*probe)(struct ub_entity *uent, const struct ub_device_id *id);
	/* entity removed (NULL if not a hot-plug capable driver) */
	void (*remove)(struct ub_entity *uent);
	void (*shutdown)(struct ub_entity *uent);
	int (*virt_configure)(struct ub_entity *uent, int entity_idx, bool is_en);
	int (*virt_notify)(struct ub_entity *uent, int entity_idx, bool is_en);
	int (*activate)(struct ub_entity *uent, u32 entity_idx);
	int (*deactivate)(struct ub_entity *uent, u32 entity_idx);
	const struct ub_error_handlers *err_handler;
	const struct attribute_group **groups;
	const struct attribute_group **dev_groups;
	struct device_driver driver;
	struct ub_dynids dynids;
	bool driver_managed_dma;

#ifndef __GENKSYMS__
	int (*reinit)(struct ub_entity *uent);
#else
	KABI_RESERVE(1)
#endif
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
	KABI_RESERVE(5)
	KABI_RESERVE(6)
	KABI_RESERVE(7)
	KABI_RESERVE(8)
};

struct ubc_common_attr {
	u32 int_id_start;
	u32 int_id_end;
	u64 hpa_base;
	u64 hpa_size;
	u8 mem_size_limit;
	u8 dma_cca;
	u16 ummu_map;
	u16 proximity_domain;
	u64 queue_addr;
	u64 queue_size;
	u16 queue_depth;
	u16 msg_int;
	u8 msg_int_attr;
	u64 ubc_guid_low;
	u64 ubc_guid_high;
};

struct ub_bus_controller {
	struct device dev;
	struct ub_entity *uent;
	struct ubc_common_attr attr;
	u32 queue_virq;
	char name[16];

	u32 ctl_no;
	struct message_device *mdev;
	struct ub_decoder *decoder;
	struct list_head resources;
	struct list_head node;
	struct list_head devs;
	struct ub_bus_controller_ops *ops;
	bool cluster;
	struct ub_bus_instance *bi;
	struct ub_bus_instance *cluster_bi;

	/* ub memory decoder */
	struct ub_mem_device *mem_device;

	void *data;
	struct dentry *debug_root;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

struct ub_bus_instance_info {
	u8 type;
	u16 upi;
	u32 eid : 20;
	struct ub_guid guid;
};

struct ub_bus_instance {
	bool registered;
	bool destroy;
	struct list_head node;
	struct kref kref;

	struct ub_bus_instance_info info;

	struct ub_bus_controller *major;

	struct list_head uents;
	struct mutex lock;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
};

#define ub_bi_is_dynamic(bi) ((bi)->info.type == UBUS_INSTANCE_DYNAMIC_SERVER \
		|| (bi)->info.type == UBUS_INSTANCE_DYNAMIC_CLUSTER)

static inline struct ub_driver *to_ub_driver(struct device_driver *drv)
{
	return drv ? container_of(drv, struct ub_driver, driver) : NULL;
}

#define ub_err(pue, fmt, arg...)	dev_err(&(pue)->dev, fmt, ##arg)
#define ub_info(pue, fmt, arg...)	dev_info(&(pue)->dev, fmt, ##arg)
#define ub_warn(pue, fmt, arg...)	dev_warn(&(pue)->dev, fmt, ##arg)
#define ub_dbg(pue, fmt, arg...)	dev_dbg(&(pue)->dev, fmt, ##arg)

static inline const char *ub_name(const struct ub_entity *pue)
{
	return dev_name(&pue->dev);
}

/* interfaces for shareable port */
enum ub_port_event {
	UB_PORT_EVENT_LINK_DOWN,
	UB_PORT_EVENT_LINK_UP,
	UB_PORT_EVENT_RESET_PREPARE,
#ifndef __GENKSYMS__
	UB_PORT_EVENT_RESET_DONE,
	UB_PORT_EVENT_RESET_FAILED
#else
	UB_PORT_EVENT_RESET_DONE
#endif
};

struct ub_share_port_ops {
	void (*reset_prepare)(struct ub_entity *uent, u16 port_id);
	void (*reset_done)(struct ub_entity *uent, u16 port_id);
	void (*event_notify)(struct ub_entity *uent, u16 port_id, int event);

	KABI_RESERVE(1)
	KABI_RESERVE(2)
};

struct ub_vdm_pld {
	void *req_pld;
	u16 req_pld_len;
	void *rsp_pld;
	u16 rsp_pld_len;
	u16 rsp_buf_len;
	u8 sub_msg_code;
};

/* feature bitmap */
#define UB_MEM_BORROW_NC BIT(0)
#define UB_MEM_BORROW_CC BIT(1)
#define UB_MEM_SHARE_NC BIT(2)
#define UB_MEM_SHARE_CC BIT(3)
#define UB_URMA_RTP_ROI BIT(16)
#define UB_URMA_RTP_ROT BIT(17)
#define UB_URMA_RTP_ROL BIT(18)
#define UB_URMA_CTP_ROI BIT(19)
#define UB_URMA_CTP_ROT BIT(20)
#define UB_URMA_CTP_ROL BIT(21)
#define UB_URMA_CTP_UNO BIT(22)
#define UB_URMA_UTP_UNO BIT(23)

#ifdef CONFIG_UB_UBUS
extern struct bus_type ub_bus_type;
#define dev_is_ub(d) ((d)->bus == &ub_bus_type)

void ub_bus_type_iommu_ops_set(const struct iommu_ops *ops);
const struct iommu_ops *ub_bus_type_iommu_ops_get(void);

/**
 * ub_get_ent_by_eid() - Searching for UB entity by EID.
 * @eid: entity EID.
 *
 * Traverse the UB bus device linked list and search for the device with
 * the target EID. You need to call ub_entity_put() after using it.
 *
 * Context: Any context.
 * Return: The entity found, or NULL if not found.
 */
struct ub_entity *ub_get_ent_by_eid(unsigned int eid);

/**
 * ub_get_ent_by_uent_num() - Searching for UB entities by entity Num.
 * @uent_num: entity Num.
 *
 * Traverse the UB bus device linked list and search for the entity with
 * the target entity Num. You need to call ub_entity_put() after using it.
 *
 * Context: Any context.
 * Return: The entity found, or NULL if not found.
 */
struct ub_entity *ub_get_ent_by_uent_num(unsigned int uent_num);

/**
 * ub_get_ent_by_guid() - Searching for UB entities by GUID.
 * @guid: GUID.
 *
 * Traverse the UB bus entity linked list and search for the entity with
 * the target GUID. You need to call ub_entity_put() after using it.
 *
 * Context: Any context.
 * Return: The entity found, or NULL if not found.
 */
struct ub_entity *ub_get_ent_by_guid(const struct ub_guid *guid);

/**
 * ub_entity_enable() - Enable or disable ub entity
 * @uent: UB entity.
 * @enable: Enable or disable.
 *
 * Deprecated: This function is going to be removed in future version.
 * Please use ub_entity_enable_return() instead, which provides more complete
 * return value processing.
 *
 * Enable or disable the communication channel between entity and user host.
 *
 * Context: Any context, it will take mutex_lock()/mutex_unlock().
 */
void ub_entity_enable(struct ub_entity *uent, u8 enable);

int ub_entity_enable_return(struct ub_entity *uent, u8 enable);

/**
 * ub_set_user_info() - Initialize host information for the entity.
 * @uent: UB entity.
 *
 * Initialize necessary host information for the entity for communication
 * purposes, such as the host EID, CNA, and token ID.
 *
 * Context: Any context.
 */
int ub_set_user_info(struct ub_entity *uent);

/**
 * ub_unset_user_info() - Deinitialize host information for the entity.
 * @uent: UB entity.
 *
 * Clearing the host information of an entity.
 *
 * Context: Any context.
 */
void ub_unset_user_info(struct ub_entity *uent);

/**
 * ub_disable_entities() - Disable UEs of MUE in batches.
 * @pue: UB MUE.
 *
 * Remove all enabled UEs under the MUE from the system.
 *
 * Context: Any context.
 */
void ub_disable_entities(struct ub_entity *pue);

/**
 * ub_enable_ue() - Enable a single ue.
 * @pue: UB MUE.
 * @entity_idx: Number of the entity to be enabled.
 *
 * Create a specified UE under MUE, initialize the ue,
 * and add it to the system.
 *
 * Context: Any context.
 * Return: 0 if success, or %-EINVAL if @pue type is not MUE or @entity_idx
 * is no longer in the UE range of MUE, or %-EEXIST if entity has been
 * enabled, or other failed negative values.
 */
int ub_enable_ue(struct ub_entity *pue, int entity_idx);

/**
 * ub_disable_ue() - Disable a single ue.
 * @pue: UB MUE.
 * @entity_idx: Number of the entity to be disabled.
 *
 * Remove a specified UE.
 *
 * Context: Any context.
 * Return: 0 if success, or %-EINVAL if @pue type is not MUE or @entity_idx
 * is no longer in the UE range of MUE, or %-ENODEV if entity hasn't
 * been enabled.
 */
int ub_disable_ue(struct ub_entity *pue, int entity_idx);

/**
 * ub_get_dst_eid() - Obtain the Dest EID of the entity.
 * @uent: UB entity.
 *
 * Return the EID of bus instance if the entity has already been bound,
 * otherwise return controller's EID.
 *
 * Context: Any context.
 * Return: positive number if success, or %-EINVAL if @dev is %NULL,
 * or %-ENODEV if entity's controller %NULL, or 0 if entity hasn't been
 * initialized.
 */
int ub_get_dst_eid(struct ub_entity *uent);

/**
 * ub_iomap() - Map the resource space of the entity.
 * @uent: UB entity.
 * @resno: Resource Number.
 * @maxlen: Map size.
 *
 * Invoke ioremap() to map the entity resource space, if maxlen is 0, then map
 * size is ub_resource_len(), else map size is min(maxlen, ub_resource_len()).
 *
 * Context: Any context.
 * Return: The return value is the same as that of ioremap().
 */
void __iomem *ub_iomap(struct ub_entity *uent, int resno, unsigned long maxlen);

/**
 * ub_iomap_wc() - Map the resource space of the entity.
 * @uent: UB entity.
 * @resno: Resource Number.
 * @maxlen: Map size.
 *
 * Invoke ioremap_wc() to map the entity resource space, if maxlen is 0,
 * then map size is ub_resource_len(), else map size is
 * min(maxlen, ub_resource_len()).
 *
 * Context: Any context.
 * Return: The return value is the same as that of ioremap_wc().
 */
void __iomem *ub_iomap_wc(struct ub_entity *uent, int resno, unsigned long maxlen);

/**
 * ub_iounmap() - Unmap the resource space of the entity.
 * @addr: Target resource address.
 *
 * Invoke iounmap() to unmap the entity resource space.
 *
 * Context: Any context.
 */
void ub_iounmap(void __iomem *addr);

/**
 * ub_register_share_port() - Register a share port.
 * @uent: UB entity.
 * @port_id: UB Bus Controller port id.
 * @ops: UB share port ops.
 *
 * The IDEV reuses the physical port of the ub bus controller. Record the
 * callback function.
 *
 * Context: Any context
 * Return: 0 if success, or %-ENOMEM if system out of memory,
 * or %-EINVAL if parameters invalid.
 */
int ub_register_share_port(struct ub_entity *uent, u16 port_id,
			   struct ub_share_port_ops *ops);

/**
 * ub_unregister_share_port() - Unregister a share port.
 * @uent: UB entity.
 * @port_id: UB Bus Controller port id.
 * @ops: UB share port ops.
 *
 * Clear the callback function.
 *
 * Context: Any context
 */
void ub_unregister_share_port(struct ub_entity *uent, u16 port_id,
			      struct ub_share_port_ops *ops);

/**
 * ub_reset_entity() - Function entity level reset.
 * @ent: UB entity.
 *
 * Reset a single entity without affecting other entities. If you want to reuse
 * the entity after reset, you need to re-initialize it.
 *
 * Context: Any context
 * Return: 0 if success, or %-EINVAL if entity not support elr,
 * or %-ENOTTY if entity can't be reset safely,
 * or -EBUSY if can't get device_trylock(), or other failed negative values.
 */
int ub_reset_entity(struct ub_entity *ent);

/**
 * ub_device_reset() - Device level reset.
 * @ent: UB entity.
 *
 * Reset device, including all entities under the device. If you want to reuse
 * the device after reset, you need to re-initialize it.
 *
 * Context: Any context
 * Return: 0 if success, or %-EINVAL if parameters invalid,
 * or %-EIO if device can't reset now, can try later.
 */
int ub_device_reset(struct ub_entity *ent);

/**
 * ub_vdm_message() - Send vendor private message.
 * @uent: UB entity.
 * @vdm_pld: Vendor private message payload context.
 *
 * Send a vendor private message to the entity. Response will be put in
 * vdm_pld->rsp_pld, and response length is stored in vdm->rsp_pld_len.
 *
 * Context: Any context, it will take spin_lock_irqsave()/spin_unlock_restore()
 * Return: 0 if success, or %-EINVAL if parameters invalid,
 * or %-ENOMEM if system out of memory, or other failed negative values.
 */
int ub_vdm_message(struct ub_entity *uent, struct ub_vdm_pld *vdm_pld);

/**
 * ub_feature_get() - Get UB controller feature sets.
 *
 * Query the vendor-specific feature capabilities of the UB controller
 * through vendor manage subsystem ops callback.
 *
 * Context: Any context.
 * Return: Feature bitmap (u64) on success,
 *	   or U64_MAX if vendor manage subsystem ops not registered or
 *	   feature_get callback not implemented.
 */
unsigned long long ub_feature_get(void);

/* Only for ubus module */
unsigned int ub_irq_calc_affinity_vectors(unsigned int minvec,
					  unsigned int maxvec,
					  const struct irq_affinity *affd);

/**
 * ub_disable_intr() - Free entity interrupt vectors.
 * @uent: UB entity.
 *
 * Free interrupt vectors of the device.
 *
 * Context: Any context.
 */
void ub_disable_intr(struct ub_entity *uent);

/**
 * ub_intr_vec_count() - Interrupt Vectors Supported by an entity.
 * @uent: UB entity.
 *
 * Querying the Number of Interrupt Vectors Supported by an entity.
 * For interrupt type 2.
 *
 * Context: Any context.
 * Return: Number of Interrupts Supported if success, or 0 if failed.
 */
u32 ub_intr_vec_count(struct ub_entity *uent);

/**
 * ub_int_type1_vec_count() - Interrupt Vectors Supported by an entity.
 * @uent: UB entity.
 *
 * Querying the Number of Interrupt Vectors Supported by an entity.
 * For interrupt type 1.
 *
 * Context: Any context.
 * Return: Number of Interrupts Supported if success, or 0 if failed.
 */
u32 ub_int_type1_vec_count(struct ub_entity *uent);

#define UB_IRQ_AFFINITY (1 << 0) /* Auto-assign affinity */
/**
 * ub_alloc_irq_vectors_affinity() - Allocate multiple entity interrupt vectors.
 * @uent: UB entity.
 * @min_vecs: minimum required number of vectors (must be >= 1).
 * @max_vecs: maximum desired number of vectors.
 *
 * @flags: allocation flags(can be 0):
 *
 *         * %UB_IRQ_AFFINITY  Auto-manage IRQs affinity by spreading
 *           the vectors around available CPUs
 *
 * @affd: affinity requirements (can be %NULL).
 *
 * Allocate interrupt vectors for the entity and set the affinity.
 *
 * Context: Any context.
 * Return: the number of vectors allocated (which might be smaller than
 * @max_vecs) if success, or a negative error code on error. If less than
 * @min_vecs interrupt vectors are available for @uent the function will
 * fail with -ENOSPC
 */
int ub_alloc_irq_vectors_affinity(struct ub_entity *uent, unsigned int min_vecs,
				  unsigned int max_vecs, unsigned int flags,
				  struct irq_affinity *affd);
static inline int ub_alloc_irq_vectors(struct ub_entity *uent,
				       unsigned int min_vecs,
				       unsigned int max_vecs)
{
	return ub_alloc_irq_vectors_affinity(uent, min_vecs, max_vecs, 0, NULL);
}

/**
 * ub_irq_vector() - Obtaining the Linux IRQ number.
 * @uent: UB entity.
 * @nr: Interrupt vector.
 *
 * Translate from Interrupt Vectors to Linux IRQ number.
 *
 * Context: Any context.
 * Return: IRQ number if success, or %-EINVAL if failed.
 */
int ub_irq_vector(struct ub_entity *uent, unsigned int nr);

/**
 * ub_irq_get_affinity() - Get an entity interrupt vector affinity
 * @uent: the UB entity to operate on
 * @nr:  entity-relative interrupt vector index (0-based); has different
 *       meanings, depending on interrupt mode:
 *
 *         * INTR_TYPE2     the index in the USI vector table
 *         * INTR_TYPE1     the index of the enabled USI vectors
 *
 * Return: USI vector affinity, NULL if @nr is out of range or if
 * the USI vector was allocated without explicit affinity
 * requirements (e.g., by ub_alloc_irq_vectors(), or
 * ub_alloc_irq_vectors_affinity() without the %UB_IRQ_AFFINITY flag).
 */
const struct cpumask *ub_irq_get_affinity(struct ub_entity *uent, int nr);

/**
 * ub_activate_entity() - Activate entity.
 * @uent: UB entity.
 * @entity_idx: Number of the entity to be activated.
 *
 * Context: Any context, it will take mutex_lock()/mutex_unlock()
 * Return: 0 if success, or %-EINVAL if the device doesn't match the driver,
 * or other failed negative values.
 */
int ub_activate_entity(struct ub_entity *uent, u32 entity_idx);

/**
 * ub_deactivate_entity() - Deactivate entity.
 * @uent: UB entity.
 * @entity_idx: Number of the entity to be deactivated.
 *
 * Context: Any context, it will take mutex_lock()/mutex_unlock()
 * Return: 0 if success, or %-EINVAL if the entity doesn't match the driver,
 * or other failed negative values.
 */
int ub_deactivate_entity(struct ub_entity *uent, u32 entity_idx);

/**
 * ub_cfg_read_byte() - 1 byte configuration access read.
 * @uent: UB entity.
 * @pos: Config space address.
 * @val: Output buffer.
 *
 * Initiate configuration access to the specified address of the entity
 * configuration space and read 1 byte.
 *
 * Context: Any context, it will take spin_lock_irqsave()/spin_unlock_restore()
 * Return: 0 if success, or negative value if failed.
 */
int ub_cfg_read_byte(struct ub_entity *uent, u64 pos, u8 *val);
int ub_cfg_read_word(struct ub_entity *uent, u64 pos, u16 *val);
int ub_cfg_read_dword(struct ub_entity *uent, u64 pos, u32 *val);
/**
 * ub_cfg_write_byte() - 1 byte configuration access write.
 * @uent: UB entity.
 * @pos: Config space address.
 * @val: Data.
 *
 * Initiate configuration access to the specified address of the entity
 * configuration space and write 1 byte.
 *
 * Context: Any context, it will take spin_lock_irqsave()/spin_unlock_restore()
 * Return: 0 if success, or negative value if failed.
 */
int ub_cfg_write_byte(struct ub_entity *uent, u64 pos, u8 val);
int ub_cfg_write_word(struct ub_entity *uent, u64 pos, u16 val);
int ub_cfg_write_dword(struct ub_entity *uent, u64 pos, u32 val);

/**
 * ub_entity_get() - Atomically increment the reference count for the entity.
 * @uent: UB entity pointer.
 *
 * Context: Any context.
 * Return: @uent itself, or NULL if @uent is NULL.
 */
struct ub_entity *ub_entity_get(struct ub_entity *uent);

/**
 * ub_entity_put() - decrement the reference count for the entity.
 * @uent: UB entity pointer.
 *
 * Context: Any context.
 */
void ub_entity_put(struct ub_entity *uent);

/**
 * ub_get_bus_controller() - Obtains the ub bus controller entity list.
 * @uents: Output buffer for the UBC entities list.
 * @max_num: Buffer size.
 * @real_num: Real entities num.
 *
 * All ub bus controllers in the system are collected in @uents. Increase the
 * reference counting of all entities by 1. Remember to call
 * ub_put_bus_controller() after using it.
 *
 * Context: Any context.
 * Return: 0 if success, or %-EINVAL if input parameter is NULL,
 * or %-ENOMEM if buffer is too small.
 */
int ub_get_bus_controller(struct ub_entity *uents[], unsigned int max_num,
			  unsigned int *real_num);

/**
 * ub_put_bus_controller() - Free the ub bus controller device list.
 * @uents: UBC entities list
 * @num: entities num
 *
 * Decrement the reference counting of all entities by 1.
 *
 * Context: Any context.
 */
void ub_put_bus_controller(struct ub_entity *uents[], unsigned int num);

/**
 * ub_cc_supported() - Congestion control capability query.
 * @uent: UB entity.
 *
 * Context: Any context.
 * Return: %true if the entity supports congestion control, %false otherwise.
 */
bool ub_cc_supported(struct ub_entity *uent);

/**
 * ub_cc_enable() - Enable the congestion control capability of the entity.
 * @uent: UB entity.
 *
 * Context: Any context.
 * Return: 0 if success, or %-EINVAL if input parameters are invalid, or
 * %-EPERM if the entity does not support congestion control, or other
 * failed negative values.
 */
int ub_cc_enable(struct ub_entity *uent);

/**
 * ub_cc_disable() - Disable the congestion control capability of the entity.
 * @uent: UB entity.
 *
 * Context: Any context.
 * Return: 0 if success, or %-EINVAL if input parameters are invalid, or
 * %-EPERM if the entity does not support congestion control, or other
 * failed negative values.
 */
int ub_cc_disable(struct ub_entity *uent);

/* Proper probing supporting hot-pluggable entities */
int __ub_register_driver(struct ub_driver *drv, struct module *owner,
			 const char *mod_name);
/* ub_register_driver() must be a macro so KBUILD_MODNAME can be expanded */
#define ub_register_driver(driver) \
	__ub_register_driver(driver, THIS_MODULE, KBUILD_MODNAME)
void ub_unregister_driver(struct ub_driver *drv);

/**
 * ub_stop_ent() - Stop the entity.
 * @uent: UB entity.
 *
 * Call device_release_driver(), user can't use it again. If it's a MUE,
 * will stop all UEs under it. If it's entity0, will stop all entities under it.
 *
 * Context: Any context.
 */
void ub_stop_ent(struct ub_entity *uent);

/**
 * ub_stop_and_remove_ent() - Stop and remove the entity from system.
 * @uent: UB entity.
 *
 * Call device_release_driver() and device_unregister(). If it's a MUE,
 * will remove all UEs under it. If it's entity0, will remove all entities
 * under it.
 *
 * Context: Any context.
 */
void ub_stop_and_remove_ent(struct ub_entity *uent);

#else /* CONFIG_UB_UBUS is not enabled */
#define dev_is_ub(d) (false)
static inline struct ub_entity *ub_get_ent_by_eid(unsigned int eid)
{ return NULL; }
static inline struct ub_entity *ub_get_ent_by_uent_num(unsigned int uent_num)
{ return NULL; }
static inline struct ub_entity *ub_get_ent_by_guid(const struct ub_guid *guid)
{ return NULL; }
static inline struct ub_entity *ub_entity_get(struct ub_entity *uent)
{ return NULL; }
static inline void ub_entity_put(struct ub_entity *uent) {}
static inline void ub_entity_enable(struct ub_entity *uent, u8 enable) {}
static inline int ub_entity_enable_return(struct ub_entity *uent, u8 enable)
{ return -ENODEV; }
static inline int ub_set_user_info(struct ub_entity *uent)
{ return -ENODEV; }
static inline void ub_unset_user_info(struct ub_entity *uent) {}
static inline void ub_disable_entities(struct ub_entity *pue) {}
static inline int ub_enable_ue(struct ub_entity *pue, int entity_idx)
{ return -ENODEV; }
static inline int ub_disable_ue(struct ub_entity *pue, int entity_idx)
{ return -ENODEV; }
static inline int ub_get_dst_eid(struct ub_entity *uent)
{ return -ENODEV; }
static inline void __iomem *
ub_iomap(struct ub_entity *uent, int resno, unsigned long maxlen)
{ return NULL; }
static inline void __iomem *
ub_iomap_wc(struct ub_entity *uent, int resno, unsigned long maxlen)
{ return NULL; }
static inline void ub_iounmap(void __iomem *addr) {}
static inline bool ub_cc_supported(struct ub_entity *uent)
{ return false; }
static inline int ub_cc_enable(struct ub_entity *uent)
{ return -ENODEV; }
static inline int ub_cc_disable(struct ub_entity *uent)
{ return -ENODEV; }
static inline int ub_cfg_read_byte(struct ub_entity *uent, u64 pos, u8 *val)
{ return -ENODEV; }
static inline int ub_cfg_read_word(struct ub_entity *uent, u64 pos, u16 *val)
{ return -ENODEV; }
static inline int ub_cfg_read_dword(struct ub_entity *uent, u64 pos, u32 *val)
{ return -ENODEV; }
static inline int ub_cfg_write_byte(struct ub_entity *uent, u64 pos, u8 val)
{ return -ENODEV; }
static inline int ub_cfg_write_word(struct ub_entity *uent, u64 pos, u16 val)
{ return -ENODEV; }
static inline int ub_cfg_write_dword(struct ub_entity *uent, u64 pos, u32 val)
{ return -ENODEV; }
static inline int ub_get_bus_controller(struct ub_entity *uents[],
				    unsigned int max_num,
				    unsigned int *real_num)
{ return -ENODEV; }
static inline void
ub_put_bus_controller(struct ub_entity *uents[], unsigned int num) {}
static inline void ub_bus_type_iommu_ops_set(const struct iommu_ops *ops) {}
static inline const struct iommu_ops *ub_bus_type_iommu_ops_get(void)
{ return NULL; }
static inline int ub_register_share_port(struct ub_entity *uent, u16 port_id,
					 struct ub_share_port_ops *ops)
{ return -ENODEV; }
static inline void ub_unregister_share_port(struct ub_entity *uent, u16 port_id,
					    struct ub_share_port_ops *ops) {}
static inline int ub_reset_entity(struct ub_entity *uent)
{ return -ENODEV; }
static inline int ub_device_reset(struct ub_entity *uent)
{ return -ENODEV; }
static inline int ub_vdm_message(struct ub_entity *uent,
				 struct ub_vdm_pld *vdm_pld)
{ return -ENODEV; }
static inline unsigned long long ub_feature_get(void)
{
	return U64_MAX;
}
static inline unsigned int
ub_irq_calc_affinity_vectors(unsigned int minvec, unsigned int maxvec,
			     const struct irq_affinity *affd)
{
	return maxvec;
}
static inline void ub_disable_intr(struct ub_entity *uent) {}
static inline u32 ub_intr_vec_count(struct ub_entity *uent)
{ return 0; }
static inline u32 ub_int_type1_vec_count(struct ub_entity *uent)
{ return 0; }
static inline int
ub_alloc_irq_vectors_affinity(struct ub_entity *uent, unsigned int min_vecs,
			      unsigned int max_vecs, unsigned int flags,
			      struct irq_affinity *affd)
{ return -ENODEV; }
static inline int ub_alloc_irq_vectors(struct ub_entity *uent,
				       unsigned int min_vecs,
				       unsigned int max_vecs)
{ return -ENODEV; }
static inline int ub_irq_vector(struct ub_entity *uent, unsigned int nr)
{ return -EINVAL; }
static inline const struct cpumask *
ub_irq_get_affinity(struct ub_entity *uent, int nr) { return cpu_possible_mask; }
static inline int ub_activate_entity(struct ub_entity *uent, u32 entity_idx)
{ return -ENODEV; }
static inline int ub_deactivate_entity(struct ub_entity *uent, u32 entity_idx)
{ return -ENODEV; }
static inline int
__ub_register_driver(struct ub_driver *drv, struct module *owner,
		     const char *mod_name)
{ return 0; }
static inline int ub_register_driver(struct ub_driver *drv)
{ return 0; }
static inline void ub_unregister_driver(struct ub_driver *drv) {}
static inline void ub_stop_ent(struct ub_entity *uent) {}
static inline void ub_stop_and_remove_ent(struct ub_entity *uent) {}
#endif /* CONFIG_UB_UBUS */

#endif /* _UB_UBUS_UBUS_H_ */
