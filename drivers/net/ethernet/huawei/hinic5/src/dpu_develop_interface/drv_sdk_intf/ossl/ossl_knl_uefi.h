/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : ossl_knl_uefi.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : UEFI kernel compatibility layer for HiNIC PCI Express Network Controller
 */

#ifndef OSSL_KNL_UEFI_H
#define OSSL_KNL_UEFI_H

#include <Uefi.h>
#include <Base.h>
#include <stdlib.h>
#include <stdbool.h>
#include <Protocol/DriverBinding.h>
#include <Protocol/DevicePath.h>
#include <Protocol/PciIo.h>
#include <Protocol/SerialIo.h>

#include <Library/BaseLib.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/PrintLib.h>
#include <IndustryStandard/Pci.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#include "HwSafeOperationLib/HwSafePrint.h"
#include "HwSafeOperationLib/HwSafeMemOpWrapper.h"
#include "base_type.h"

/* global var */
#define __iomem
typedef UINT64 dma_addr_t;
typedef UINT64 phys_addr_t;
typedef EFI_LOCK spinlock_t;

typedef enum irqreturn irqreturn_t;
typedef irqreturn_t (*irq_handler_t)(int, void *);
typedef u64 uintptr_t;

#define module_init(name)
#define module_exit(name)
#define module_param(name, type, perm)
#define	module_param_array_named(name, names, type, nump, perm)

#define MODULE_LICENSE(_license)
#define MODULE_PARM_DESC(_parm, desc)
#define MODULE_PARM(_parm, desc)

#define EXPORT_SYMBOL(name)
#define EXPORT_SYMBOL_GPL(name)

#define LONG_MAX ((long)(~0UL>>1))

#define HINIC5_CFG_BAR      1
#define HINIC5_INTR_BAR     2
#define HINIC5_MGMT_BAR     3
#define HINIC5_DB_BAR       4

struct mutex {
	EFI_LOCK mutex_lock;
};

struct dma_pool {
	UINT32  size;
	VOID *dev_hdl;
};

typedef struct {
	INT32 counter;
} atomic_t;

struct attribute {
	char *name;
};

struct semaphore {
	EFI_LOCK sem;
};

typedef void (*simulated_irq)(void *hwdev);

struct ifla_vf_info {
	UINT32 vf;
	UINT8 mac[32];
	UINT32 vlan;
	UINT32 qos;
	UINT32 spoofchk;
	UINT32 linkstate;
	UINT32 tx_rate;
	UINT32 max_tx_rate;
	UINT32 min_tx_rate;
	UINT32 trusted;
};

struct completion {
	INT32 done;
	simulated_irq simulated_irq_instance;
	VOID *hwdev;
};

enum hinic5_wq_type {
	HINIC5_WQ_FOR_MBX,
	HINIC5_WQ_FOR_MGMT
};

struct workqueue_struct {
	void *work_hdl;
	enum hinic5_wq_type wq_type;
};

struct list_head {
	unsigned long RetrievalCode;
	struct list_head *pNext;
};

struct timer_list {
	EFI_EVENT  timer;
	UINT64 expires; // jiffess
	void (*function)(unsigned long);
	UINT64 data;
};

struct tasklet_struct {
	void (*fun)(ulong);
	void *data;
	BOOLEAN bEnable;
};

struct work_struct;
typedef void (*work_func_t)(struct work_struct *work);

typedef struct work_struct {
	work_func_t foo;
	void *data;
	UINT64 pengding;
	struct workqueue_struct *wq;
	UINT64 timeout;
	EFI_EVENT timer;
} work_struct;

struct msix_entry {
	UINT32	vector;
	UINT16	entry;
};

enum irqreturn {
	IRQ_NONE = (0 << 0),
	IRQ_HANDLED = (1 << 0),
	IRQ_WAKE_THREAD = (1 << 1),
};

struct pci_dev {
    /* struct device must be first elment */
	EFI_PCI_IO_PROTOCOL *dev;
	UINTN   vendor;
	UINTN   device;
	struct msix_entry *entries;
	UINT16 maxmsicnt;
	spinlock_t pci_dev_lock;
};

struct device {
    /* struct device must be first elment */
	EFI_PCI_IO_PROTOCOL *dev;
};

/* define linux kernel data */
#define SZ_1K       0x00000400
#define SZ_2K       0x00000800
#define SZ_4K       0x00001000
#define SZ_8K       0x00002000
#define SZ_16K      0x00004000
#define SZ_32K      0x00008000
#define SZ_64K      0x00010000
#define SZ_128K     0x00020000
#define SZ_256K     0x00040000

#define __GFP_COMP  0
#define GFP_KERNEL  0
#define GFP_ATOMIC  0

#define PAGE_SHIFT  12
#define PAGE_SIZE   SZ_4K

#define EfiBusIoWidthUint32 EfiPciIoWidthUint32
#define EfiBusIoWidthUint64 EfiPciIoWidthUint64
#define EFI_BUS_IO_PROTOCOL_WIDTH EFI_PCI_IO_PROTOCOL_WIDTH

#define EfiBusIoAttributeOperationSupported         EfiPciIoAttributeOperationSupported
#define EfiBusIoAttributeOperationEnable            EfiPciIoAttributeOperationEnable
#define EfiBusIoAttributeOperationSet               EfiPciIoAttributeOperationSet
#define EfiBusIoAttributeOperationGet               EfiPciIoAttributeOperationGet
#define EfiBusIoOperationBusMasterCommonBuffer      EfiPciIoOperationBusMasterCommonBuffer
#define EFI_BUS_IO_PROTOCOL_ATTRIBUTE_OPERATION     EFI_PCI_IO_PROTOCOL_ATTRIBUTE_OPERATION
#define EFI_BUS_IO_PROTOCOL_OPERATION               EFI_PCI_IO_PROTOCOL_OPERATION

typedef struct BUS_IO_PROTOCOL BUS_IO_PROTOCOL;

typedef EFI_STATUS (EFIAPI *EFI_BUS_IO_PROTOCOL_ALLOCATE_BUFFER)(
	IN  BUS_IO_PROTOCOL              *This,
	IN  EFI_ALLOCATE_TYPE            Type,
	IN  EFI_MEMORY_TYPE              MemoryType,
	IN  UINTN                        Pages,
	OUT VOID                         **HostAddress,
	IN  UINT64                       Attributes
);

typedef EFI_STATUS (EFIAPI *EFI_BUS_IO_PROTOCOL_FREE_BUFFER)(
	IN  BUS_IO_PROTOCOL              *This,
	IN  UINTN                        Pages,
	IN  VOID                         *HostAddress
);

typedef EFI_STATUS (EFIAPI *EFI_BUS_IO_PROTOCOL_IO_MEM)(
	IN     BUS_IO_PROTOCOL              *This,
	IN     EFI_BUS_IO_PROTOCOL_WIDTH    Width,
	IN     UINT8                        BarIndex,
	IN     UINT64                       Offset,
	IN     UINTN                        Count,
	IN OUT VOID                         *Buffer
);

typedef EFI_STATUS (EFIAPI *EFI_BUS_IO_PROTOCOL_ATTRIBUTES)(
	IN  BUS_IO_PROTOCOL                          *This,
	IN  EFI_BUS_IO_PROTOCOL_ATTRIBUTE_OPERATION  Operation,
	IN  UINT64                                   Attributes,
	OUT UINT64                                   *Result OPTIONAL
);

typedef EFI_STATUS (EFIAPI *EFI_BUS_IO_PROTOCOL_MAP)(
	IN     BUS_IO_PROTOCOL                *This,
	IN     EFI_BUS_IO_PROTOCOL_OPERATION  Operation,
	IN     VOID                           *HostAddress,
	IN OUT UINTN                          *NumberOfBytes,
	OUT    EFI_PHYSICAL_ADDRESS           *DeviceAddress,
	OUT    VOID                           **Mapping
);

typedef EFI_STATUS (EFIAPI *EFI_BUS_IO_PROTOCOL_UNMAP)(
	IN  BUS_IO_PROTOCOL              *This,
	IN  VOID                         *Mapping
);

typedef struct {
	EFI_BUS_IO_PROTOCOL_IO_MEM    Read;
	EFI_BUS_IO_PROTOCOL_IO_MEM    Write;
} EFI_BUS_IO_PROTOCOL_ACCESS;

typedef struct BUS_IO_PROTOCOL {
	EFI_BUS_IO_PROTOCOL_ALLOCATE_BUFFER     AllocateBuffer;
	EFI_BUS_IO_PROTOCOL_FREE_BUFFER         FreeBuffer;
	EFI_BUS_IO_PROTOCOL_ACCESS              Mem;
	EFI_BUS_IO_PROTOCOL_ATTRIBUTES          Attributes;
	EFI_BUS_IO_PROTOCOL_MAP                 Map;
	EFI_BUS_IO_PROTOCOL_UNMAP               Unmap;
	VOID                                    *BusHdl;
} BUS_IO_PROTOCOL;

enum {
	EPERM = 1,    /* Operation not permitted */
	ENOENT = 2,   /* No such file or directory */
	ESRCH = 3,    /* No such process */
	EINTR = 4,    /* Interrupted system call */
	EIO   = 5,    /* I/O error */
	ENXIO = 6,    /* No such device or address */
	E2BIG = 7,    /* Argument list too long */
	ENOEXEC = 8,  /* Exec format error */
	EBADF = 9,    /* Bad file number */
	ECHILD = 10,  /* No child processes */
	EAGAIN = 11,  /* Try again */
	ENOMEM = 12,  /* Out of memory */
	EACCES = 13,  /* Permission denied */
	EFAULT = 14,  /* Bad address */
	ENOTBLK = 15, /* Block device required */
	EBUSY = 16,   /* Device or resource busy */
	EEXIST = 17,  /* File exists */
	EXDEV = 18,   /* Cross-device link */
	ENODEV = 19,  /* No such device */
	ENOTDIR = 20, /* Not a directory */
	EISDIR = 21,  /* Is a directory */
	EINVAL = 22,  /* Invalid argument */
	ENFILE = 23,  /* File table overflow */
	EMFILE = 24,  /* Too many open files */
	ENOTTY = 25,  /* Not a typewriter */
	ETXTBSY = 26, /* Text file busy */
	EFBIG = 27,   /* File too large */
	ENOSPC = 28,  /* No space left on device */
	ESPIPE = 29,  /* Illegal seek */
	EROFS = 30,   /* Read-only file system */
	EMLINK = 31,  /* Too many links */
	EPIPE = 32,   /* Broken pipe */
	EDOM = 33,    /* Math argument out of domain of func */
	ERANGE = 34,  /* Math result not representable */
	EWOULDBLOCK = EAGAIN, /* Operation would block */
	EINPROGRESS = 36, /* Operation now in progress */
	EALREADY = 37, /* Operation already in progress */
	ENOTSOCK = 38, /* Socket operation on non-socket */
	EDESTADDRREQ = 39, /* Destination address required */
	EMSGSIZE = 40, /* Message too long */
	EPROTOTYPE = 41, /* Protocol wrong type for socket */
	ENOPROTOOPT = 42, /* Protocol not available */
	EPROTONOSUPPORT = 43, /* Protocol not supported */
	ESOCKTNOSUPPORT = 44, /* Socket type not supported */
	EOPNOTSUPP = 45, /* Operation not supported on transport endpoint */
	EPFNOSUPPORT = 46, /* Protocol family not supported */
	EAFNOSUPPORT = 47, /* Address family not supported by protocol */
	EADDRINUSE = 48, /* Address already in use */
	EADDRNOTAVAIL = 49, /* Cannot assign requested address */
	ENETDOWN = 50, /* Network is down */
	ENETUNREACH = 51, /* Network is unreachable */
	ENETRESET = 52, /* Network dropped connection because of reset */
	ECONNABORTED = 53, /* Software caused connection abort */
	ECONNRESET = 54, /* Connection reset by peer */
	ENOBUFS = 55, /* No buffer space available */
	EISCONN = 56, /* Transport endpoint is already connected */
	ENOTCONN = 57, /* Transport endpoint is not connected */
	ESHUTDOWN = 58, /* Cannot send after transport endpoint shutdown */
	ETOOMANYREFS = 59, /* Too many references: cannot splice */
	ETIMEDOUT = 60, /* Connection timed out */
	ECONNREFUSED = 61, /* Connection refused */
	ELOOP = 62,    /* Too many symbolic links encountered */
	ENAMETOOLONG = 63, /* File name too long */
	EHOSTDOWN = 64, /* Host is down */
	EHOSTUNREACH = 65, /* No route to host */
	ENOTEMPTY = 66, /* Directory not empty */
};

#define ETH_ALEN        6       /* Octets in one ethernet addr   */
#define ETH_HLEN        14      /* Total octets in header.       */
#define ETH_ZLEN        60      /* Min. octets in frame sans FCS */
#define ETH_DATA_LEN    1500    /* Max. octets in payload        */
#define ETH_FRAME_LEN   1514    /* Max. octets in frame sans FCS */
#define ETH_FCS_LEN     4       /* Octets in the FCS             */
#define ETH_MIN_MTU     68      /* Min IPv4 MTU per RFC791       */

#define VLAN_PRIO_MASK          0xe000 /* Priority Code Point */
#define VLAN_PRIO_SHIFT         13
#define VLAN_CFI_MASK           0x1000 /* Canonical Format Indicator */
#define VLAN_TAG_PRESENT        VLAN_CFI_MASK
#define VLAN_VID_MASK           0x0fff /* VLAN Identifier */
#define VLAN_N_VID              4096

#define IS_ERR(a) (!(a))

#define min(a, b) MIN(a, b)
#define max(a, b) MAX(a, b)
#define min_t(t, a, b) MIN(a, b)
#define max_t(t, a, b) MAX(a, b)

#define BIT(nr)         (1UL << (nr))
#define BIT_ULL(nr)     (1ULL << (nr))
#define INT_BIT_WIDTH	32
#define INT_BIT_SHIFT	5

#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))
#define lower_32_bits(n) ((u32)(n))

dma_addr_t virt_to_phys(VOID *vaddr);

UINT16 ilog2(int n);

VOID EFIAPI EfiSerialPortPrint(IN UINTN ErrorLevel, IN CONST CHAR8 *Format, ...);
#ifdef __Taishan__
#define DebugPrint EfiSerialPortPrint
#endif

/** Returns offset of member in structure
	@param[in]   st   Structure type
	@param[in]   m    Structure member
	@return    Offset of member from structure in bytes
**/
#define offsetof_type(st, m) ((size_t)((char *)&((st *)(0))->m - (char *)0))

#define container_of(ptr, type, member) ({                  \
	const typeof(((type *)0)->member) *__mptr = (ptr);    \
	(type *)((char *)__mptr - offsetof_type(type, member)); })

/**
 * ALIGN - aligns number to specified granularity
 * @x: number
 * @a: granularity
 * @return: number aligned to granularity
 */
#define ALIGN(x, a) (((x) + ((UINT64) (a) - 1)) & ~((UINT64) (a) - 1))
#define ____cacheline_aligned

#define time_before(a, b) ((a) < (b))
#define time_after(a, b) time_before(b, a)

unsigned long get_jiffies(VOID);
#define jiffies get_jiffies()

unsigned long msecs_to_jiffies(unsigned long m);
unsigned long jiffies_to_msecs(unsigned long n);

/*
 * The struct used to pass data via the following ioctl. Similar to the
 * struct tm in <time.h>, but it needs to be here so that the kernel
 * source is self contained, allowing cross-compiles, etc. etc.
 */

struct rtc_time {
	int tm_sec;
	int tm_min;
	int tm_hour;
	int tm_mday;
	int tm_mon;
	int tm_year;
	int tm_wday;
	int tm_yday;
	int tm_isdst;
};

#define UEFI_LEAPS_THRU_END_OF(y) (((y) / 4 - (y) / 100) + (y) / 400)
void do_gettimeofday(struct timeval *tv);
void rtc_time_to_tm(unsigned long time, struct rtc_time *tm);

#define roundup_pow_of_two(n)			\
	(((n) == 1) ? 1 : (1UL << (ilog2((n) - 1) + 1)))

UINT64 cpu_to_be64(UINT64 x);
UINT32 cpu_to_be32(UINT32 x);
UINT16 cpu_to_be16(UINT16 x);
UINT64 be64_to_cpu(UINT64 x);
UINT32 be32_to_cpu(UINT32 x);
UINT16 be16_to_cpu(UINT16 x);

void atomic_inc(atomic_t *v);
void atomic_dec(atomic_t *v);
void atomic_set(atomic_t *addr, int newval);
int atomic_read(atomic_t *v);
void atomic_add(int i, atomic_t *v);
void atomic_sub(int i, atomic_t *v);
int atomic_add_return(int i, atomic_t *v);
int atomic_sub_return(int i, atomic_t *v);
int atomic_cmpxchg(atomic_t *v, int oldval, int newval);
void *_kzalloc(size_t size, ulong flags);
void *kcalloc(size_t n, size_t size, ulong flags);
void _kfree(void *p);
void *_vzalloc(size_t size);
void _vfree(void *p);

#define destroy_completion(completion)
#define sema_deinit(lock)
#define mutex_deinit(lock)

#define DIV_ROUND_UP(n, d)   (((n) + (d) - 1) / (d))
#define BITS_PER_BYTE       8
#define BITS_TO_LONGS(nr)   DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))

#define DECLARE_BITMAP(name, bits) unsigned long name[BITS_TO_LONGS(bits)]

void bitmap_copy(unsigned long *dst, const unsigned long *src, int nbits);
void bitmap_zero(unsigned long *dst, int nbits);
void _set_bit(long nr, volatile unsigned long *addr);
void _clear_bit(long nr, volatile unsigned long *addr);
int _test_bit(long nr, volatile unsigned long *addr);

#define kzalloc(size, flag) _kzalloc(size, flag)
#define	NUMA_NO_NODE        (-1)
#define dev_to_node(pdev)   NUMA_NO_NODE

#ifndef gfp_t
#define gfp_t unsigned
#endif

VOID dma_free_coherent(VOID *handle, size_t size, VOID *cpu_addr,
			dma_addr_t dma_handle);

VOID *dma_zalloc_coherent(VOID *handle, size_t size, dma_addr_t *DeviceAddress,
				ulong flag);
#define dma_alloc_coherent dma_zalloc_coherent
struct dma_pool *dma_pool_create(char *name, void *dev_hdl, size_t size,
					size_t align, size_t allocation);
void dma_pool_destroy(struct dma_pool *pool);

VOID msleep(UINT32 mstime);
VOID usleep(UINT32 ustime);
VOID usleep_range(UINT32 mix, UINT32 max);

VOID spin_lock_init(spinlock_t *lock);
VOID spin_lock_deinit(spinlock_t *lock);
VOID spin_lock_bh(spinlock_t *lock);
VOID spin_unlock_bh(spinlock_t *lock);
void sema_init(struct semaphore *sem, int val);
void down(struct semaphore *sem);
void up(struct semaphore *sem);
void init_completion(struct completion *x);
#define reinit_completion       init_completion
BOOLEAN wait_for_completion_timeout(struct completion *x,
					unsigned long timeout);
BOOLEAN try_wait_for_completion(struct completion *x);
void wait_for_completion(struct completion *x);
void complete(struct completion *x);
void mutex_init(struct mutex *lock);
int mutex_trylock(struct mutex *lock);
void mutex_lock(struct mutex *lock);
void mutex_unlock(struct mutex *lock);
void *io_mapping_map_wc(void *ignored1, UINT64 ignored2);
void io_mapping_unmap(void *ignored);
UINT16 hinic5_adev_irq_vectors_alloc(void *dev, struct msix_entry *entries,
					int minvec, UINT16 maxvec);
UINT16 hinic5_adev_irq_vector(struct msix_entry *entry, u16 i);
#define hinic5_adev_irq_vectors_free(adev)

#define dev_name(dev) "dev"

void synchronize_irq(UINT32 irq);

#define WQ_MEM_RECLAIM	0x8U

void cancel_work_sync(struct work_struct *work);
struct workqueue_struct *create_singlethread_workqueue(char *name);
struct workqueue_struct *alloc_workqueue(const char *fmt, unsigned int flags,
						int max_active, ...);

void destroy_workqueue(struct workqueue_struct *wq);
void destroy_work(struct work_struct *work);
int queue_work(struct workqueue_struct *wq, struct work_struct *work);
void flush_workqueue(struct workqueue_struct *wq);
void tasklet_init(struct tasklet_struct *t, void (*func)(unsigned long),
			unsigned long data);
#define tasklet_schedule(t)
#define tasklet_kill(t)
#define tasklet_state(tasklet) 1

#define queue_work_on(cpu, wq, work)   queue_work(wq, work)

/* bypass timer functions */
void initialize_timer(void *adapter_hdl, struct timer_list *timer);
void add_to_timer(struct timer_list *timer, UINT64 period);
void stop_timer(struct timer_list *timer);
void delete_timer(struct timer_list *timer);
void mod_timer(struct timer_list *timer, UINT64 expires);

#define LINUX_VERSION_CODE 2
#define KERNEL_VERSION(i, j, k) 1
#define CRITICAL  (1 << 10)

#define wmb()       MemoryFence()
#define smp_rmb()   MemoryFence()
#define rmb()       MemoryFence()
#define dma_rmb()   rmb()

#define spin_lock_irqsave(lock, flags) spin_lock_bh(lock)
#define spin_unlock_irqrestore(lock, flags) spin_unlock_bh(lock)
#define spin_lock(lock) spin_lock_bh(lock)
#define spin_unlock(lock) spin_unlock_bh(lock)
#define	dma_pool_alloc(pool, flags, handle) \
	dma_zalloc_coherent((pool->dev_hdl), (pool->size), (handle), (flags))
#define dma_pool_free(pool, vaddr, addr)    \
	dma_free_coherent((pool->dev_hdl), (pool->size), (vaddr), (addr))

#define DEBUGPRINT(Lvl, Msg, ...) \
	do { \
	if (Lvl != 0) { \
		DebugPrint (0x2, Msg, ##__VA_ARGS__); \
		DebugPrint (0x2, "\n"); \
	} \
	} while (0)

#define likely
#define unlikely

#define pr_err(fmt, ...) DEBUGPRINT(CRITICAL, fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...) DEBUGPRINT(CRITICAL, fmt, ##__VA_ARGS__)

static inline void __attribute__ ((unused)) Hinic5GetTime(UINT8 *min, UINT8 *second,
							UINT32 *ns)
{
	EFI_STATUS Status;
	EFI_TIME Time = {0};

	Status = gRT->GetTime(&Time, NULL);
	if (EFI_ERROR(Status)) {
	DebugPrint(DEBUG_ERROR, "GetTime not success, returns %r\n", Status);
	}

	*min = Time.Minute;
	*second = Time.Second;
	*ns = Time.Nanosecond;
}

#define dev_err(dev, fmt, ...) \
	do {    \
	dev = dev; \
	u8 min = 0; \
	u8 second = 0; \
	u32 ns = 0; \
	Hinic5GetTime(&min, &second, &ns); \
	DEBUGPRINT(CRITICAL, "[%u:%u:%u]"fmt, min, second, ns, ##__VA_ARGS__); \
	} while (0)

#define dev_warn(dev, fmt, ...) \
	do {    \
	dev = dev; \
	u8 min = 0; \
	u8 second = 0; \
	u32 ns = 0; \
	Hinic5GetTime(&min, &second, &ns); \
	DEBUGPRINT(CRITICAL, "[%u:%u:%u]"fmt, min, second, ns, ##__VA_ARGS__); \
	} while (0)

#define dev_warn_once(dev, fmt, ...) \
	do {    \
	static bool __print_once; \
	if (!__print_once) { \
		__print_once = true; \
		dev_warn(dev, fmt, ##__VA_ARGS__); \
	} \
	} while (0)

#define dev_notice(dev, fmt, ...) \
	do {    \
	dev = dev; \
	DEBUGPRINT(CRITICAL, fmt, ##__VA_ARGS__); \
	} while (0)

#define dev_info(dev, fmt, ...) \
	do {    \
	dev = dev; \
	DEBUGPRINT(CRITICAL, fmt, ##__VA_ARGS__); \
	} while (0)

#define dev_dbg(dev, fmt, ...) \
	do {    \
	dev = dev; \
	DEBUGPRINT(CRITICAL, fmt, ##__VA_ARGS__); \
	} while (0)

#define BITS_PER_LONG 64

int request_irq(unsigned int irq, irq_handler_t handler, unsigned long flags,
		const char *name, void *dev);
void free_irq(UINT32 irq, void *dev);

void INIT_WORK(struct work_struct *work,
		void (*eq_irq_work)(struct work_struct *work));
UINT8 work_busy(struct work_struct *work);

#define BITMAP_LAST_WORD_MASK(nbits) (~0UL >> (-(nbits) & (BITS_PER_LONG - 1)))
#define set_bit(nr, dest)   _set_bit((long)(nr), (ulong *)(dest))
#define clear_bit(nr, dest) _clear_bit((long)(nr), (ulong *)(dest))
#define test_bit(nr, dest)  _test_bit((long)(nr), (ulong *)(dest))

unsigned long *bitmap_zalloc(unsigned int nbits, gfp_t flags);
int find_first_zero_bit(const unsigned long *vaddr, unsigned size);

#define kfree           _kfree
#define vzalloc(size)   _vzalloc(size)
#define vfree(p)        _vfree(p)

#define SIZE_MAX	(~(size_t)0)
#define vmalloc(size) _vzalloc(size)
#define kmalloc(size, flag) _kzalloc(size, flag)

void ether_addr_copy(UINT8 *dst, const UINT8 *src);

UINT32 readl_uefi(BUS_IO_PROTOCOL *BusIO, UINT32 reg, UINT8 bar_idx);
void writel_uefi(BUS_IO_PROTOCOL *BusIO, UINT32 reg, UINT8 bar_idx,
			UINT32 val);
void writeq_uefi(BUS_IO_PROTOCOL *BusIO, UINT64 reg, UINT8 bar_idx,
			UINT64 val);

#ifndef ether_addr_equal
#define ether_addr_equal(addr1, addr2) !CompareMem(addr1, addr2, ETH_ALEN)
#endif

#ifndef eth_zero_addr
#define eth_zero_addr(addr) ZeroMem(addr, ETH_ALEN)
#endif

static inline BOOLEAN is_multicast_ether_addr(const UINT8 *addr)
{
	return 0x01 & addr[0];
}

static inline BOOLEAN is_zero_ether_addr(const UINT8 *addr)
{
	return !(addr[0x0] | addr[0x1] | addr[0x2] | addr[0x3] | addr[0x4] | addr[0x5]);
}

static inline int is_valid_ether_addr(const UINT8 *addr)
{
    /* FF:FF:FF:FF:FF:FF is a multicast address so we don't need to
     * explicitly check for it here.
     */
	return !is_multicast_ether_addr(addr) && !is_zero_ether_addr(addr);
}

static inline int fls(unsigned int x)
{
	int i;

	if (x == 0) {
	return 0;
	}

    /* 32 bit for unsigned int */
	for (i = 32; i > 0; i--) {
	if ((x & (1U << (unsigned int)(i - 1))) != 0) {
		break;
	}
	}

	return i;
}

#define USEC_PER_MSEC	1000L

#define WORK_CPU_UNBOUND    0

/* Adapting to the CQM */
typedef struct {
	unsigned long pgprot;
} pgprot_t;

#define PAGE_KERNEL     ((pgprot_t) {(x)}) /* these mean nothing to non MMU */

#ifndef gfp_t
#define gfp_t unsigned
#endif

#define rwlock_t spinlock_t
#define __GFP_ZERO  0
#define DMA_BIDIRECTIONAL   0
#define get_order(x) HighBitSet32(EFI_SIZE_TO_PAGES(x))
#define VM_MAP    0x00000004   /* vmap()ed pages */

#define __swab64(value) cpu_to_be64(value)
#define __swab32(value) cpu_to_be32(value)

#define read_lock(lock) spin_lock_bh(lock)
#define read_unlock(lock) spin_unlock_bh(lock)
#define write_lock(lock) spin_lock_bh(lock)
#define write_unlock(lock) spin_unlock_bh(lock)

#define read_lock_bh(lock) read_lock(lock)
#define read_unlock_bh(lock) read_unlock(lock)
#define write_lock_bh(lock) write_lock(lock)
#define write_unlock_bh(lock) write_unlock(lock)

#define rwlock_init(lock) spin_lock_init(lock)
#define rwlock_deinit(lock)

#define vmap(pages, page_number, flag1, flag2) pages
#define vunmap(a)
#define page_address(page) page

void *get_free_pages(UINT32 order);
void free_pages(UINT64 addr, UINT32 order);
#define __get_free_pages(gfp_mask, order) \
	({ (void)(gfp_mask); get_free_pages(order); })
#define ossl_get_free_pages	__get_free_pages

static inline dma_addr_t dma_map_single(struct device *dev, void *ptr,
					size_t size, int direction)
{
	return (dma_addr_t)ptr;
}

static inline void dma_unmap_single(struct device *dev, dma_addr_t dma_addr,
					size_t size, int direction) { }

static inline int dma_mapping_error(struct device *dev,
					dma_addr_t dma_addr)
{
	return 0;
}

static inline struct page *virt_to_page(void *ptr)
{
	return (struct page *)ptr;
}

static inline struct page *alloc_pages_node(int nid, gfp_t gfp_mask,
						unsigned int order)
{
	return get_free_pages(order);
}

static inline int find_next_zero_bit(const unsigned long *addr,
					unsigned long size,
					unsigned long offset)
{
	int i = 0;

	for (i = (int)offset; i < (int)size; i++) {
	if (test_bit(i, addr) == 0) {
		return i;
	}
	}

	return i;
}

static inline INT64 atomic_dec_and_test(atomic_t *v)
{
	EFI_TPL OldTpl;
	INT32 r = 0;

	OldTpl = gBS->RaiseTPL(TPL_HIGH_LEVEL);
	r = v->counter;
	v->counter = v->counter - 1;
	gBS->RestoreTPL(OldTpl);

	return (INT64)(r == 1);
}

struct msi_msg {
	u32	address_lo;
	u32	address_hi;
	u32	data;
};

/* MSI-X Table entry format */
#define  PCI_MSIX_ENTRY_SIZE		16
#define  PCI_MSIX_ENTRY_LOWER_ADDR	0
#define  PCI_MSIX_ENTRY_UPPER_ADDR	4
#define  PCI_MSIX_ENTRY_DATA		8

#ifndef WARN_ON
#define WARN_ON(condition) ({			\
	bool __ret_warn_on = !!(condition);	\
	unlikely(__ret_warn_on);		\
})
#endif

#ifndef WARN_ON_ONCE
#define WARN_ON_ONCE(condition) ({		\
	bool __ret_warn_on = !!(condition);	\
	unlikely(__ret_warn_on);		\
})
#endif

#endif
