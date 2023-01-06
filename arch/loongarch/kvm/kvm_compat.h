#ifndef __LOONGARCH_KVM_COMPAT_H__
#define __LOONGARCH_KVM_COMPAT_H__

#ifdef __ASSEMBLY__
#define _ULCAST_
#else
#define _ULCAST_ (unsigned long)
#include <linux/version.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
#include <loongson.h>
#else
#include <asm/loongarch.h>
#endif
#endif

#define KVM_REG_A0		0x4
#define KVM_REG_A1		0x5
#define KVM_REG_A2		0x6
#define KVM_REG_A3		0x7
/*
 * ExStatus.ExcCode
 */
#define KVM_EXCCODE_RSV		0	/* Reserved */
#define KVM_EXCCODE_TLBL	1	/* TLB miss on a load */
#define KVM_EXCCODE_TLBS	2	/* TLB miss on a store */
#define KVM_EXCCODE_TLBI	3	/* TLB miss on a ifetch */
#define KVM_EXCCODE_TLBM	4	/* TLB modified fault */
#define KVM_EXCCODE_TLBRI	5	/* TLB Read-Inhibit exception */
#define KVM_EXCCODE_TLBXI	6	/* TLB Execution-Inhibit exception */
#define KVM_EXCCODE_TLBPE	7	/* TLB Privilege Error */
#define KVM_EXCCODE_ADE		8	/* Address Error */
#define KVM_EXCCODE_ALE		9	/* Unalign Access */
#define KVM_EXCCODE_OOB		10	/* Out of bounds */
#define KVM_EXCCODE_SYS		11	/* System call */
#define KVM_EXCCODE_BP		12	/* Breakpoint */
#define KVM_EXCCODE_INE		13	/* Inst. Not Exist */
#define KVM_EXCCODE_IPE		14	/* Inst. Privileged Error */
#define KVM_EXCCODE_FPDIS	15	/* FPU Disabled */
#define KVM_EXCCODE_LSXDIS	16	/* LSX Disabled */
#define KVM_EXCCODE_LASXDIS	17	/* LASX Disabled */
#define KVM_EXCCODE_FPE		18	/* Floating Point Exception */
#define KVM_EXCCODE_WATCH	19	/* Watch address reference */
#define KVM_EXCCODE_BTDIS	20	/* Binary Trans. Disabled */
#define KVM_EXCCODE_BTE		21	/* Binary Trans. Exception */
#define KVM_EXCCODE_GSPR	22	/* Guest Privileged Error */
#define KVM_EXCCODE_HYP		23	/* Hypercall */
#define KVM_EXCCODE_GCM		24	/* Guest CSR modified */

#define KVM_INT_START		64
#define KVM_INT_SIP0		64
#define KVM_INT_SIP1		65
#define KVM_INT_IP0		66
#define KVM_INT_IP1		67
#define KVM_INT_IP2		68
#define KVM_INT_IP3		69
#define KVM_INT_IP4		70
#define KVM_INT_IP5		71
#define KVM_INT_IP6		72
#define KVM_INT_IP7		73
#define KVM_INT_PC		74 /* Performance Counter */
#define KVM_INT_TIMER		75
#define KVM_INT_IPI		76
#define KVM_INT_NMI		77
#define KVM_INT_END		78
#define KVM_INT_NUM		(KVM_INT_END - KVM_INT_START)

#define KVM_CSR_CRMD		0x0	/* Current mode info */
#define KVM_CRMD_WE_SHIFT	9
#define KVM_CRMD_WE		(_ULCAST_(0x1) << KVM_CRMD_WE_SHIFT)
#define KVM_CRMD_DACM_SHIFT	7
#define KVM_CRMD_DACM_WIDTH	2
#define KVM_CRMD_DACM		(_ULCAST_(0x3) << KVM_CRMD_DACM_SHIFT)
#define KVM_CRMD_DACF_SHIFT	5
#define KVM_CRMD_DACF_WIDTH	2
#define KVM_CRMD_DACF		(_ULCAST_(0x3) << KVM_CRMD_DACF_SHIFT)
#define KVM_CRMD_PG_SHIFT	4
#define KVM_CRMD_PG		(_ULCAST_(0x1) << KVM_CRMD_PG_SHIFT)
#define KVM_CRMD_DA_SHIFT	3
#define KVM_CRMD_DA		(_ULCAST_(0x1) << KVM_CRMD_DA_SHIFT)
#define KVM_CRMD_IE_SHIFT	2
#define KVM_CRMD_IE		(_ULCAST_(0x1) << KVM_CRMD_IE_SHIFT)
#define KVM_CRMD_PLV_SHIFT	0
#define KVM_CRMD_PLV_WIDTH	2
#define KVM_CRMD_PLV		(_ULCAST_(0x3) << KVM_CRMD_PLV_SHIFT)

#define KVM_CSR_PRMD		0x1	/* Prev-exception mode info */
#define KVM_PRMD_PIE_SHIFT	2
#define KVM_PRMD_PWE_SHIFT	3
#define KVM_PRMD_PIE		(_ULCAST_(0x1) << KVM_PRMD_PIE_SHIFT)
#define KVM_PRMD_PWE		(_ULCAST_(0x1) << KVM_PRMD_PWE_SHIFT)
#define KVM_PRMD_PPLV_SHIFT	0
#define KVM_PRMD_PPLV_WIDTH	2
#define KVM_PRMD_PPLV		(_ULCAST_(0x3) << KVM_PRMD_PPLV_SHIFT)

#define KVM_CSR_EUEN		0x2	/* Extended unit enable */
#define KVM_EUEN_LBTEN_SHIFT	3
#define KVM_EUEN_LBTEN		(_ULCAST_(0x1) << KVM_EUEN_LBTEN_SHIFT)
#define KVM_EUEN_LASXEN_SHIFT	2
#define KVM_EUEN_LASXEN		(_ULCAST_(0x1) << KVM_EUEN_LASXEN_SHIFT)
#define KVM_EUEN_LSXEN_SHIFT	1
#define KVM_EUEN_LSXEN		(_ULCAST_(0x1) << KVM_EUEN_LSXEN_SHIFT)
#define KVM_EUEN_FPEN_SHIFT	0
#define KVM_EUEN_FPEN		(_ULCAST_(0x1) << KVM_EUEN_FPEN_SHIFT)

#define KVM_CSR_MISC		0x3	/* Misc config */
#define KVM_CSR_ECFG		0x4	/* Exception config */
#define KVM_ECFG_VS_SHIFT	16
#define KVM_ECFG_VS_WIDTH	3
#define KVM_ECFG_VS		(_ULCAST_(0x7) << KVM_ECFG_VS_SHIFT)
#define KVM_ECFG_IM_SHIFT	0
#define KVM_ECFG_IM_WIDTH	13
#define KVM_ECFG_IM		(_ULCAST_(0x1fff) << KVM_ECFG_IM_SHIFT)

#define KVM_CSR_ESTAT			0x5	/* Exception status */
#define KVM_ESTAT_ESUBCODE_SHIFT	22
#define KVM_ESTAT_ESUBCODE_WIDTH	9
#define KVM_ESTAT_ESUBCODE		(_ULCAST_(0x1ff) << KVM_ESTAT_ESUBCODE_SHIFT)
#define KVM_ESTAT_EXC_SHIFT		16
#define KVM_ESTAT_EXC_WIDTH		6
#define KVM_ESTAT_EXC			(_ULCAST_(0x3f) << KVM_ESTAT_EXC_SHIFT)
#define KVM_ESTAT_IS_SHIFT		0
#define KVM_ESTAT_IS_WIDTH		15
#define KVM_ESTAT_IS			(_ULCAST_(0x7fff) << KVM_ESTAT_IS_SHIFT)

#define KVM_CSR_ERA			0x6	/* ERA */
#define KVM_CSR_BADV			0x7	/* Bad virtual address */
#define KVM_CSR_BADI			0x8	/* Bad instruction */
#define KVM_CSR_EENTRY			0xc	/* Exception entry base address */
#define KVM_CSR_TLBIDX			0x10	/* TLB Index, EHINV, PageSize, NP */
#define KVM_CSR_TLBEHI			0x11	/* TLB EntryHi */
#define KVM_CSR_TLBELO0			0x12	/* TLB EntryLo0 */
#define KVM_CSR_TLBELO1			0x13	/* TLB EntryLo1 */
#define KVM_CSR_GTLBC			0x15	/* Guest TLB control */
#define KVM_GTLBC_TGID_SHIFT		16
#define KVM_GTLBC_TGID_WIDTH		8
#define KVM_GTLBC_TGID			(_ULCAST_(0xff) << KVM_GTLBC_TGID_SHIFT)
#define KVM_GTLBC_TOTI_SHIFT		13
#define KVM_GTLBC_TOTI			(_ULCAST_(0x1) << KVM_GTLBC_TOTI_SHIFT)
#define KVM_GTLBC_USETGID_SHIFT		12
#define KVM_GTLBC_USETGID		(_ULCAST_(0x1) << KVM_GTLBC_USETGID_SHIFT)
#define KVM_GTLBC_GMTLBSZ_SHIFT		0
#define KVM_GTLBC_GMTLBSZ_WIDTH		6
#define KVM_GTLBC_GMTLBSZ		(_ULCAST_(0x3f) << KVM_GTLBC_GMTLBSZ_SHIFT)

#define KVM_CSR_TRGP			0x16	/* TLBR read guest info */
#define KVM_CSR_ASID			0x18	/* ASID */
#define KVM_CSR_PGDL			0x19	/* Page table base address when VA[47] = 0 */
#define KVM_CSR_PGDH			0x1a	/* Page table base address when VA[47] = 1 */
#define KVM_CSR_PGD			0x1b	/* Page table base */
#define KVM_CSR_PWCTL0			0x1c	/* PWCtl0 */
#define KVM_CSR_PWCTL1			0x1d	/* PWCtl1 */
#define KVM_CSR_STLBPGSIZE		0x1e
#define KVM_CSR_RVACFG			0x1f
#define KVM_CSR_CPUID			0x20	/* CPU core number */
#define KVM_CSR_PRCFG1			0x21	/* Config1 */
#define KVM_CSR_PRCFG2			0x22	/* Config2 */
#define KVM_CSR_PRCFG3			0x23	/* Config3 */
#define KVM_CSR_KS0			0x30
#define KVM_CSR_KS1			0x31
#define KVM_CSR_KS2			0x32
#define KVM_CSR_KS3			0x33
#define KVM_CSR_KS4			0x34
#define KVM_CSR_KS5			0x35
#define KVM_CSR_KS6			0x36
#define KVM_CSR_KS7			0x37
#define KVM_CSR_KS8			0x38
#define KVM_CSR_TMID			0x40	/* Timer ID */
#define KVM_CSR_TCFG			0x41	/* Timer config */
#define KVM_TCFG_VAL_SHIFT		2
#define KVM_TCFG_VAL_WIDTH		48
#define KVM_TCFG_VAL			(_ULCAST_(0x3fffffffffff) << KVM_TCFG_VAL_SHIFT)
#define KVM_TCFG_PERIOD_SHIFT		1
#define KVM_TCFG_PERIOD			(_ULCAST_(0x1) << KVM_TCFG_PERIOD_SHIFT)
#define KVM_TCFG_EN			(_ULCAST_(0x1))

#define KVM_CSR_TVAL			0x42	/* Timer value */
#define KVM_CSR_CNTC			0x43	/* Timer offset */
#define KVM_CSR_TINTCLR			0x44	/* Timer interrupt clear */
#define KVM_CSR_GSTAT			0x50	/* Guest status */
#define KVM_GSTAT_GID_SHIFT		16
#define KVM_GSTAT_GID_WIDTH		8
#define KVM_GSTAT_GID			(_ULCAST_(0xff) << KVM_GSTAT_GID_SHIFT)
#define KVM_GSTAT_GIDBIT_SHIFT		4
#define KVM_GSTAT_GIDBIT_WIDTH		6
#define KVM_GSTAT_GIDBIT		(_ULCAST_(0x3f) << KVM_GSTAT_GIDBIT_SHIFT)
#define KVM_GSTAT_PVM_SHIFT		1
#define KVM_GSTAT_PVM			(_ULCAST_(0x1) << KVM_GSTAT_PVM_SHIFT)
#define KVM_GSTAT_VM_SHIFT		0
#define KVM_GSTAT_VM			(_ULCAST_(0x1) << KVM_GSTAT_VM_SHIFT)

#define KVM_CSR_GCFG			0x51	/* Guest config */
#define KVM_GCFG_GPERF_SHIFT		24
#define KVM_GCFG_GPERF_WIDTH		3
#define KVM_GCFG_GPERF			(_ULCAST_(0x7) << KVM_GCFG_GPERF_SHIFT)
#define KVM_GCFG_GCI_SHIFT		20
#define KVM_GCFG_GCI_WIDTH		2
#define KVM_GCFG_GCI			(_ULCAST_(0x3) << KVM_GCFG_GCI_SHIFT)
#define KVM_GCFG_GCI_ALL		(_ULCAST_(0x0) << KVM_GCFG_GCI_SHIFT)
#define KVM_GCFG_GCI_HIT		(_ULCAST_(0x1) << KVM_GCFG_GCI_SHIFT)
#define KVM_GCFG_GCI_SECURE		(_ULCAST_(0x2) << KVM_GCFG_GCI_SHIFT)
#define KVM_GCFG_GCIP_SHIFT		16
#define KVM_GCFG_GCIP			(_ULCAST_(0xf) << KVM_GCFG_GCIP_SHIFT)
#define KVM_GCFG_GCIP_ALL		(_ULCAST_(0x1) << KVM_GCFG_GCIP_SHIFT)
#define KVM_GCFG_GCIP_HIT		(_ULCAST_(0x1) << (KVM_GCFG_GCIP_SHIFT + 1))
#define KVM_GCFG_GCIP_SECURE		(_ULCAST_(0x1) << (KVM_GCFG_GCIP_SHIFT + 2))
#define KVM_GCFG_TORU_SHIFT		15
#define KVM_GCFG_TORU			(_ULCAST_(0x1) << KVM_GCFG_TORU_SHIFT)
#define KVM_GCFG_TORUP_SHIFT		14
#define KVM_GCFG_TORUP			(_ULCAST_(0x1) << KVM_GCFG_TORUP_SHIFT)
#define KVM_GCFG_TOP_SHIFT		13
#define KVM_GCFG_TOP			(_ULCAST_(0x1) << KVM_GCFG_TOP_SHIFT)
#define KVM_GCFG_TOPP_SHIFT		12
#define KVM_GCFG_TOPP			(_ULCAST_(0x1) << KVM_GCFG_TOPP_SHIFT)
#define KVM_GCFG_TOE_SHIFT		11
#define KVM_GCFG_TOE			(_ULCAST_(0x1) << KVM_GCFG_TOE_SHIFT)
#define KVM_GCFG_TOEP_SHIFT		10
#define KVM_GCFG_TOEP			(_ULCAST_(0x1) << KVM_GCFG_TOEP_SHIFT)
#define KVM_GCFG_TIT_SHIFT		9
#define KVM_GCFG_TIT			(_ULCAST_(0x1) << KVM_GCFG_TIT_SHIFT)
#define KVM_GCFG_TITP_SHIFT		8
#define KVM_GCFG_TITP			(_ULCAST_(0x1) << KVM_GCFG_TITP_SHIFT)
#define KVM_GCFG_SIT_SHIFT		7
#define KVM_GCFG_SIT			(_ULCAST_(0x1) << KVM_GCFG_SIT_SHIFT)
#define KVM_GCFG_SITP_SHIFT		6
#define KVM_GCFG_SITP			(_ULCAST_(0x1) << KVM_GCFG_SITP_SHIFT)
#define KVM_GCFG_MATC_SHITF		4
#define KVM_GCFG_MATC_WIDTH		2
#define KVM_GCFG_MATC_MASK		(_ULCAST_(0x3) << KVM_GCFG_MATC_SHITF)
#define KVM_GCFG_MATC_GUEST		(_ULCAST_(0x0) << KVM_GCFG_MATC_SHITF)
#define KVM_GCFG_MATC_ROOT		(_ULCAST_(0x1) << KVM_GCFG_MATC_SHITF)
#define KVM_GCFG_MATC_NEST		(_ULCAST_(0x2) << KVM_GCFG_MATC_SHITF)
#define KVM_GCFG_MATP_SHITF		0
#define KVM_GCFG_MATP_WIDTH		4
#define KVM_GCFG_MATR_MASK		(_ULCAST_(0x3) << KVM_GCFG_MATP_SHITF)
#define KVM_GCFG_MATP_GUEST		(_ULCAST_(0x0) << KVM_GCFG_MATP_SHITF)
#define KVM_GCFG_MATP_ROOT		(_ULCAST_(0x1) << KVM_GCFG_MATP_SHITF)
#define KVM_GCFG_MATP_NEST		(_ULCAST_(0x2) << KVM_GCFG_MATP_SHITF)

#define KVM_CSR_GINTC			0x52	/* Guest interrupt control */
#define KVM_CSR_GCNTC			0x53	/* Guest timer offset */
#define KVM_CSR_LLBCTL			0x60	/* LLBit control */
#define KVM_LLBCTL_ROLLB_SHIFT		0
#define KVM_LLBCTL_ROLLB		(_ULCAST_(1) << KVM_LLBCTL_ROLLB_SHIFT)
#define KVM_LLBCTL_WCLLB_SHIFT		1
#define KVM_LLBCTL_WCLLB		(_ULCAST_(1) << KVM_LLBCTL_WCLLB_SHIFT)
#define KVM_LLBCTL_KLO_SHIFT		2
#define KVM_LLBCTL_KLO			(_ULCAST_(1) << KVM_LLBCTL_KLO_SHIFT)

#define KVM_CSR_IMPCTL1		0x80	/* Loongson config1 */
#define KVM_CSR_IMPCTL2		0x81	/* Loongson config2 */
#define KVM_CSR_GNMI		0x82
#define KVM_CSR_TLBRENTRY	0x88	/* TLB refill exception base address */
#define KVM_CSR_TLBRBADV	0x89	/* TLB refill badvaddr */
#define KVM_CSR_TLBRERA		0x8a	/* TLB refill ERA */
#define KVM_CSR_TLBRSAVE	0x8b	/* KScratch for TLB refill exception */
#define KVM_CSR_TLBRELO0	0x8c	/* TLB refill entrylo0 */
#define KVM_CSR_TLBRELO1	0x8d	/* TLB refill entrylo1 */
#define KVM_CSR_TLBREHI		0x8e	/* TLB refill entryhi */
#define KVM_CSR_TLBRPRMD	0x8f	/* TLB refill mode info */
#define KVM_CSR_ERRCTL		0x90	/* ERRCTL */
#define KVM_CSR_ERRINFO1	0x91	/* Error info1 */
#define KVM_CSR_ERRINFO2	0x92	/* Error info2 */
#define KVM_CSR_MERRENTRY	0x93	/* Error exception base address */
#define KVM_CSR_MERRERA		0x94	/* Error exception PC */
#define KVM_CSR_ERRSAVE		0x95	/* KScratch for machine error exception */
#define KVM_CSR_CTAG		0x98	/* TagLo + TagHi */
#define KVM_CSR_DMWIN0		0x180	/* 64 direct map win0: MEM & IF */
#define KVM_CSR_DMWIN1		0x181	/* 64 direct map win1: MEM & IF */
#define KVM_CSR_DMWIN2		0x182	/* 64 direct map win2: MEM */
#define KVM_CSR_DMWIN3		0x183	/* 64 direct map win3: MEM */
#define KVM_CSR_PERFCTRL0	0x200	/* 32 perf event 0 config */
#define KVM_CSR_PERFCNTR0	0x201	/* 64 perf event 0 count value */
#define KVM_CSR_PERFCTRL1	0x202	/* 32 perf event 1 config */
#define KVM_CSR_PERFCNTR1	0x203	/* 64 perf event 1 count value */
#define KVM_CSR_PERFCTRL2	0x204	/* 32 perf event 2 config */
#define KVM_CSR_PERFCNTR2	0x205	/* 64 perf event 2 count value */
#define KVM_CSR_PERFCTRL3	0x206	/* 32 perf event 3 config */
#define KVM_CSR_PERFCNTR3	0x207	/* 64 perf event 3 count value */
#define KVM_PERFCTRL_PLV0	(_ULCAST_(1) << 16)
#define KVM_PERFCTRL_PLV1	(_ULCAST_(1) << 17)
#define KVM_PERFCTRL_PLV2	(_ULCAST_(1) << 18)
#define KVM_PERFCTRL_PLV3	(_ULCAST_(1) << 19)
#define KVM_PERFCTRL_IE		(_ULCAST_(1) << 20)
#define KVM_PERFCTRL_GMOD	(_ULCAST_(3) << 21)
#define KVM_PERFCTRL_EVENT	0x3ff

#define KVM_CSR_MWPC		0x300	/* data breakpoint config */
#define KVM_CSR_MWPS		0x301	/* data breakpoint status */
#define KVM_CSR_FWPC		0x380	/* instruction breakpoint config */
#define KVM_CSR_FWPS		0x381	/* instruction breakpoint status */
#define KVM_CSR_DEBUG		0x500	/* debug config */
#define KVM_CSR_DERA		0x501	/* debug era */
#define KVM_CSR_DESAVE		0x502	/* debug save */

#define KVM_IOCSR_FEATURES			0x8
#define KVM_IOCSRF_TEMP				BIT_ULL(0)
#define KVM_IOCSRF_NODECNT			BIT_ULL(1)
#define KVM_IOCSRF_MSI				BIT_ULL(2)
#define KVM_IOCSRF_EXTIOI			BIT_ULL(3)
#define KVM_IOCSRF_CSRIPI			BIT_ULL(4)
#define KVM_IOCSRF_FREQCSR			BIT_ULL(5)
#define KVM_IOCSRF_FREQSCALE			BIT_ULL(6)
#define KVM_IOCSRF_DVFSV1			BIT_ULL(7)
#define KVM_IOCSRF_EXTIOI_DECODE		BIT_ULL(9)
#define KVM_IOCSRF_FLATMODE			BIT_ULL(10)
#define KVM_IOCSRF_VM				BIT_ULL(11)

#define KVM_IOCSR_VENDOR			0x10
#define KVM_IOCSR_CPUNAME			0x20
#define KVM_IOCSR_NODECNT			0x408

#define KVM_IOCSR_MISC_FUNC			0x420
#define KVM_IOCSRF_MISC_FUNC_EXT_IOI_EN		BIT_ULL(48)

/* PerCore CSR, only accessable by local cores */
#define KVM_IOCSR_IPI_STATUS			0x1000
#define KVM_IOCSR_IPI_SEND			0x1040
#define KVM_IOCSR_MBUF_SEND			0x1048
#define KVM_IOCSR_EXTIOI_NODEMAP_BASE		0x14a0
#define KVM_IOCSR_EXTIOI_IPMAP_BASE		0x14c0
#define KVM_IOCSR_EXTIOI_EN_BASE		0x1600
#define KVM_IOCSR_EXTIOI_BOUNCE_BASE		0x1680
#define KVM_IOCSR_EXTIOI_ISR_BASE		0x1800
#define KVM_IOCSR_EXTIOI_ROUTE_BASE		0x1c00

#ifndef __ASSEMBLY__

/* CSR */
static inline u32 kvm_csr_readl(u32 reg)
{
	u32 val;

	asm volatile (
		"csrrd %[val], %[reg] \n"
		: [val] "=r" (val)
		: [reg] "i" (reg)
		: "memory");
	return val;
}

static inline u64 kvm_csr_readq(u32 reg)
{
	u64 val;

	asm volatile (
		"csrrd %[val], %[reg] \n"
		: [val] "=r" (val)
		: [reg] "i" (reg)
		: "memory");
	return val;
}

static inline void kvm_csr_writel(u32 val, u32 reg)
{
	asm volatile (
		"csrwr %[val], %[reg] \n"
		: [val] "+r" (val)
		: [reg] "i" (reg)
		: "memory");
}

static inline void kvm_csr_writeq(u64 val, u32 reg)
{
	asm volatile (
		"csrwr %[val], %[reg] \n"
		: [val] "+r" (val)
		: [reg] "i" (reg)
		: "memory");
}

static inline u32 kvm_csr_xchgl(u32 val, u32 mask, u32 reg)
{
	asm volatile (
		"csrxchg %[val], %[mask], %[reg] \n"
		: [val] "+r" (val)
		: [mask] "r" (mask), [reg] "i" (reg)
		: "memory");
	return val;
}

static inline u64 kvm_csr_xchgq(u64 val, u64 mask, u32 reg)
{
	asm volatile (
		"csrxchg %[val], %[mask], %[reg] \n"
		: [val] "+r" (val)
		: [mask] "r" (mask), [reg] "i" (reg)
		: "memory");
	return val;
}


/* IOCSR */
static inline u32 kvm_iocsr_readl(u32 reg)
{
	u32 val;

	asm volatile (
		"iocsrrd.w %[val], %[reg] \n"
		: [val] "=r" (val)
		: [reg] "r" (reg)
		: "memory");
	return val;
}

static inline u64 kvm_iocsr_readq(u32 reg)
{
	u64 val;

	asm volatile (
		"iocsrrd.d %[val], %[reg] \n"
		: [val] "=r" (val)
		: [reg] "r" (reg)
		: "memory");
	return val;
}

static inline void kvm_iocsr_writeb(u8 val, u32 reg)
{
	asm volatile (
		"iocsrwr.b %[val], %[reg] \n"
		:
		: [val] "r" (val), [reg] "r" (reg)
		: "memory");
}

static inline void kvm_iocsr_writel(u32 val, u32 reg)
{
	asm volatile (
		"iocsrwr.w %[val], %[reg] \n"
		:
		: [val] "r" (val), [reg] "r" (reg)
		: "memory");
}

static inline void kvm_iocsr_writeq(u64 val, u32 reg)
{
	asm volatile (
		"iocsrwr.d %[val], %[reg] \n"
		:
		: [val] "r" (val), [reg] "r" (reg)
		: "memory");
}


/* GCSR */
static inline u64 kvm_gcsr_read(u32 reg)
{
	u64 val = 0;

	asm volatile (
	"parse_r __reg, %[val]	\n"
	".word 0x5 << 24 | %[reg] << 10 | 0 << 5 | __reg	\n"
	: [val] "+r" (val)
	: [reg] "i" (reg)
	: "memory");
	return val;
}

static inline void kvm_gcsr_write(u64 val, u32 reg)
{
	asm volatile (
	"parse_r __reg, %[val]	\n"
	".word 0x5 << 24 | %[reg] << 10 | 1 << 5 | __reg	\n"
	: [val] "+r" (val)
	: [reg] "i" (reg)
	: "memory");
}

static inline u64 kvm_gcsr_xchg(u64 val, u64 mask, u32 reg)
{
	asm volatile (
	"parse_r __rd, %[val]	\n"
	"parse_r __rj, %[mask]	\n"
	".word 0x5 << 24 | %[reg] << 10 | __rj << 5 | __rd	\n"
	: [val] "+r" (val)
	: [mask] "r" (mask), [reg] "i" (reg)
	: "memory");
	return val;
}

#endif /* !__ASSEMBLY__ */

#define kvm_read_csr_euen()		kvm_csr_readq(KVM_CSR_EUEN)
#define kvm_write_csr_euen(val)		kvm_csr_writeq(val, KVM_CSR_EUEN)
#define kvm_read_csr_ecfg()		kvm_csr_readq(KVM_CSR_ECFG)
#define kvm_write_csr_ecfg(val)		kvm_csr_writeq(val, KVM_CSR_ECFG)
#define kvm_write_csr_perfctrl0(val)	kvm_csr_writeq(val, KVM_CSR_PERFCTRL0)
#define kvm_write_csr_perfcntr0(val)	kvm_csr_writeq(val, LOONGARCH_CSR_PERFCNTR0)
#define kvm_write_csr_perfctrl1(val)	kvm_csr_writeq(val, LOONGARCH_CSR_PERFCTRL1)
#define kvm_write_csr_perfcntr1(val)	kvm_csr_writeq(val, LOONGARCH_CSR_PERFCNTR1)
#define kvm_write_csr_perfctrl2(val)	kvm_csr_writeq(val, LOONGARCH_CSR_PERFCTRL2)
#define kvm_write_csr_perfcntr2(val)	kvm_csr_writeq(val, LOONGARCH_CSR_PERFCNTR2)
#define kvm_write_csr_perfctrl3(val)	kvm_csr_writeq(val, LOONGARCH_CSR_PERFCTRL3)
#define kvm_write_csr_perfcntr3(val)	kvm_csr_writeq(val, LOONGARCH_CSR_PERFCNTR3)
#define kvm_read_csr_impctl1()		kvm_csr_readq(LOONGARCH_CSR_IMPCTL1)
#define kvm_write_csr_impctl1(val)	kvm_csr_writeq(val, LOONGARCH_CSR_IMPCTL1)


/* Guest related CSRS */
#define kvm_read_csr_gtlbc()		kvm_csr_readq(KVM_CSR_GTLBC)
#define kvm_write_csr_gtlbc(val)	kvm_csr_writeq(val, KVM_CSR_GTLBC)
#define kvm_read_csr_trgp()		kvm_csr_readq(KVM_CSR_TRGP)
#define kvm_read_csr_gcfg()		kvm_csr_readq(KVM_CSR_GCFG)
#define kvm_write_csr_gcfg(val)		kvm_csr_writeq(val, KVM_CSR_GCFG)
#define kvm_read_csr_gstat()		kvm_csr_readq(KVM_CSR_GSTAT)
#define kvm_write_csr_gstat(val)	kvm_csr_writeq(val, KVM_CSR_GSTAT)
#define kvm_read_csr_gintc()		kvm_csr_readq(KVM_CSR_GINTC)
#define kvm_write_csr_gintc(val)	kvm_csr_writeq(val, KVM_CSR_GINTC)
#define kvm_read_csr_gcntc()		kvm_csr_readq(KVM_CSR_GCNTC)
#define kvm_write_csr_gcntc(val)	kvm_csr_writeq(val, KVM_CSR_GCNTC)

/* Guest CSRS read and write */
#define kvm_read_gcsr_crmd()		kvm_gcsr_read(KVM_CSR_CRMD)
#define kvm_write_gcsr_crmd(val)	kvm_gcsr_write(val, KVM_CSR_CRMD)
#define kvm_read_gcsr_prmd()		kvm_gcsr_read(KVM_CSR_PRMD)
#define kvm_write_gcsr_prmd(val)	kvm_gcsr_write(val, KVM_CSR_PRMD)
#define kvm_read_gcsr_euen()		kvm_gcsr_read(KVM_CSR_EUEN)
#define kvm_write_gcsr_euen(val)	kvm_gcsr_write(val, KVM_CSR_EUEN)
#define kvm_read_gcsr_misc()		kvm_gcsr_read(KVM_CSR_MISC)
#define kvm_write_gcsr_misc(val)	kvm_gcsr_write(val, KVM_CSR_MISC)
#define kvm_read_gcsr_ecfg()		kvm_gcsr_read(KVM_CSR_ECFG)
#define kvm_write_gcsr_ecfg(val)	kvm_gcsr_write(val, KVM_CSR_ECFG)
#define kvm_read_gcsr_estat()		kvm_gcsr_read(KVM_CSR_ESTAT)
#define kvm_write_gcsr_estat(val)	kvm_gcsr_write(val, KVM_CSR_ESTAT)
#define kvm_read_gcsr_era()		kvm_gcsr_read(KVM_CSR_ERA)
#define kvm_write_gcsr_era(val)		kvm_gcsr_write(val, KVM_CSR_ERA)
#define kvm_read_gcsr_badv()		kvm_gcsr_read(KVM_CSR_BADV)
#define kvm_write_gcsr_badv(val)	kvm_gcsr_write(val, KVM_CSR_BADV)
#define kvm_read_gcsr_badi()		kvm_gcsr_read(KVM_CSR_BADI)
#define kvm_write_gcsr_badi(val)	kvm_gcsr_write(val, KVM_CSR_BADI)
#define kvm_read_gcsr_eentry()		kvm_gcsr_read(KVM_CSR_EENTRY)
#define kvm_write_gcsr_eentry(val)	kvm_gcsr_write(val, KVM_CSR_EENTRY)

#define kvm_read_gcsr_tlbidx()		kvm_gcsr_read(KVM_CSR_TLBIDX)
#define kvm_write_gcsr_tlbidx(val)	kvm_gcsr_write(val, KVM_CSR_TLBIDX)
#define kvm_read_gcsr_tlbhi()		kvm_gcsr_read(KVM_CSR_TLBEHI)
#define kvm_write_gcsr_tlbhi(val)	kvm_gcsr_write(val, KVM_CSR_TLBEHI)
#define kvm_read_gcsr_tlblo0()		kvm_gcsr_read(KVM_CSR_TLBELO0)
#define kvm_write_gcsr_tlblo0(val)	kvm_gcsr_write(val, KVM_CSR_TLBELO0)
#define kvm_read_gcsr_tlblo1()		kvm_gcsr_read(KVM_CSR_TLBELO1)
#define kvm_write_gcsr_tlblo1(val)	kvm_gcsr_write(val, KVM_CSR_TLBELO1)

#define kvm_read_gcsr_asid()		kvm_gcsr_read(KVM_CSR_ASID)
#define kvm_write_gcsr_asid(val)	kvm_gcsr_write(val, KVM_CSR_ASID)
#define kvm_read_gcsr_pgdl()		kvm_gcsr_read(KVM_CSR_PGDL)
#define kvm_write_gcsr_pgdl(val)	kvm_gcsr_write(val, KVM_CSR_PGDL)
#define kvm_read_gcsr_pgdh()		kvm_gcsr_read(KVM_CSR_PGDH)
#define kvm_write_gcsr_pgdh(val)	kvm_gcsr_write(val, KVM_CSR_PGDH)
#define kvm_write_gcsr_pgd(val)		kvm_gcsr_write(val, KVM_CSR_PGD)
#define kvm_read_gcsr_pgd()		kvm_gcsr_read(KVM_CSR_PGD)
#define kvm_read_gcsr_pwctl0()		kvm_gcsr_read(KVM_CSR_PWCTL0)
#define kvm_write_gcsr_pwctl0(val)	kvm_gcsr_write(val, KVM_CSR_PWCTL0)
#define kvm_read_gcsr_pwctl1()		kvm_gcsr_read(KVM_CSR_PWCTL1)
#define kvm_write_gcsr_pwctl1(val)	kvm_gcsr_write(val, KVM_CSR_PWCTL1)
#define kvm_read_gcsr_stlbpgsize()	kvm_gcsr_read(KVM_CSR_STLBPGSIZE)
#define kvm_write_gcsr_stlbpgsize(val)	kvm_gcsr_write(val, KVM_CSR_STLBPGSIZE)
#define kvm_read_gcsr_rvacfg()		kvm_gcsr_read(KVM_CSR_RVACFG)
#define kvm_write_gcsr_rvacfg(val)	kvm_gcsr_write(val, KVM_CSR_RVACFG)

#define kvm_read_gcsr_cpuid()		kvm_gcsr_read(KVM_CSR_CPUID)
#define kvm_write_gcsr_cpuid(val)	kvm_gcsr_write(val, KVM_CSR_CPUID)
#define kvm_read_gcsr_prcfg1()		kvm_gcsr_read(KVM_CSR_PRCFG1)
#define kvm_write_gcsr_prcfg1(val)	kvm_gcsr_write(val, KVM_CSR_PRCFG1)
#define kvm_read_gcsr_prcfg2()		kvm_gcsr_read(KVM_CSR_PRCFG2)
#define kvm_write_gcsr_prcfg2(val)	kvm_gcsr_write(val, KVM_CSR_PRCFG2)
#define kvm_read_gcsr_prcfg3()		kvm_gcsr_read(KVM_CSR_PRCFG3)
#define kvm_write_gcsr_prcfg3(val)	kvm_gcsr_write(val, KVM_CSR_PRCFG3)

#define kvm_read_gcsr_kscratch0()	kvm_gcsr_read(KVM_CSR_KS0)
#define kvm_write_gcsr_kscratch0(val)	kvm_gcsr_write(val, KVM_CSR_KS0)
#define kvm_read_gcsr_kscratch1()	kvm_gcsr_read(KVM_CSR_KS1)
#define kvm_write_gcsr_kscratch1(val)	kvm_gcsr_write(val, KVM_CSR_KS1)
#define kvm_read_gcsr_kscratch2()	kvm_gcsr_read(KVM_CSR_KS2)
#define kvm_write_gcsr_kscratch2(val)	kvm_gcsr_write(val, KVM_CSR_KS2)
#define kvm_read_gcsr_kscratch3()	kvm_gcsr_read(KVM_CSR_KS3)
#define kvm_write_gcsr_kscratch3(val)	kvm_gcsr_write(val, KVM_CSR_KS3)
#define kvm_read_gcsr_kscratch4()	kvm_gcsr_read(KVM_CSR_KS4)
#define kvm_write_gcsr_kscratch4(val)	kvm_gcsr_write(val, KVM_CSR_KS4)
#define kvm_read_gcsr_kscratch5()	kvm_gcsr_read(KVM_CSR_KS5)
#define kvm_write_gcsr_kscratch5(val)	kvm_gcsr_write(val, KVM_CSR_KS5)
#define kvm_read_gcsr_kscratch6()	kvm_gcsr_read(KVM_CSR_KS6)
#define kvm_write_gcsr_kscratch6(val)	kvm_gcsr_write(val, KVM_CSR_KS6)
#define kvm_read_gcsr_kscratch7()	kvm_gcsr_read(KVM_CSR_KS7)
#define kvm_write_gcsr_kscratch7(val)	kvm_gcsr_write(val, KVM_CSR_KS7)

#define kvm_read_gcsr_timerid()		kvm_gcsr_read(KVM_CSR_TMID)
#define kvm_write_gcsr_timerid(val)	kvm_gcsr_write(val, KVM_CSR_TMID)
#define kvm_read_gcsr_timercfg()	kvm_gcsr_read(KVM_CSR_TCFG)
#define kvm_write_gcsr_timercfg(val)	kvm_gcsr_write(val, KVM_CSR_TCFG)
#define kvm_read_gcsr_timertick()	kvm_gcsr_read(KVM_CSR_TVAL)
#define kvm_write_gcsr_timertick(val)	kvm_gcsr_write(val, KVM_CSR_TVAL)
#define kvm_read_gcsr_timeroffset()	kvm_gcsr_read(KVM_CSR_CNTC)
#define kvm_write_gcsr_timeroffset(val)	kvm_gcsr_write(val, KVM_CSR_CNTC)

#define kvm_read_gcsr_llbctl()		kvm_gcsr_read(KVM_CSR_LLBCTL)
#define kvm_write_gcsr_llbctl(val)	kvm_gcsr_write(val, KVM_CSR_LLBCTL)

#define kvm_read_gcsr_tlbrentry()	kvm_gcsr_read(KVM_CSR_TLBRENTRY)
#define kvm_write_gcsr_tlbrentry(val)	kvm_gcsr_write(val, KVM_CSR_TLBRENTRY)
#define kvm_read_gcsr_tlbrbadv()	kvm_gcsr_read(KVM_CSR_TLBRBADV)
#define kvm_write_gcsr_tlbrbadv(val)	kvm_gcsr_write(val, KVM_CSR_TLBRBADV)
#define kvm_read_gcsr_tlbrera()		kvm_gcsr_read(KVM_CSR_TLBRERA)
#define kvm_write_gcsr_tlbrera(val)	kvm_gcsr_write(val, KVM_CSR_TLBRERA)
#define kvm_read_gcsr_tlbrsave()	kvm_gcsr_read(KVM_CSR_TLBRSAVE)
#define kvm_write_gcsr_tlbrsave(val)	kvm_gcsr_write(val, KVM_CSR_TLBRSAVE)
#define kvm_read_gcsr_tlbrelo0()	kvm_gcsr_read(KVM_CSR_TLBRELO0)
#define kvm_write_gcsr_tlbrelo0(val)	kvm_gcsr_write(val, KVM_CSR_TLBRELO0)
#define kvm_read_gcsr_tlbrelo1()	kvm_gcsr_read(KVM_CSR_TLBRELO1)
#define kvm_write_gcsr_tlbrelo1(val)	kvm_gcsr_write(val, KVM_CSR_TLBRELO1)
#define kvm_read_gcsr_tlbrehi()		kvm_gcsr_read(KVM_CSR_TLBREHI)
#define kvm_write_gcsr_tlbrehi(val)	kvm_gcsr_write(val, KVM_CSR_TLBREHI)
#define kvm_read_gcsr_tlbrprmd()	kvm_gcsr_read(KVM_CSR_TLBRPRMD)
#define kvm_write_gcsr_tlbrprmd(val)	kvm_gcsr_write(val, KVM_CSR_TLBRPRMD)

#define kvm_read_gcsr_directwin0()	kvm_gcsr_read(KVM_CSR_DMWIN0)
#define kvm_write_gcsr_directwin0(val)	kvm_gcsr_write(val, KVM_CSR_DMWIN0)
#define kvm_read_gcsr_directwin1()	kvm_gcsr_read(KVM_CSR_DMWIN1)
#define kvm_write_gcsr_directwin1(val)	kvm_gcsr_write(val, KVM_CSR_DMWIN1)
#define kvm_read_gcsr_directwin2()	kvm_gcsr_read(KVM_CSR_DMWIN2)
#define kvm_write_gcsr_directwin2(val)	kvm_gcsr_write(val, KVM_CSR_DMWIN2)
#define kvm_read_gcsr_directwin3()	kvm_gcsr_read(KVM_CSR_DMWIN3)
#define kvm_write_gcsr_directwin3(val)	kvm_gcsr_write(val, KVM_CSR_DMWIN3)

#ifndef __ASSEMBLY__

static inline unsigned long
kvm_set_csr_gtlbc(unsigned long set)
{
	unsigned long res, new;

	res = kvm_read_csr_gtlbc();
	new = res | set;
	kvm_write_csr_gtlbc(new);

	return res;
}

static inline unsigned long
kvm_set_csr_euen(unsigned long set)
{
	unsigned long res, new;

	res = kvm_read_csr_euen();
	new = res | set;
	kvm_write_csr_euen(new);

	return res;
}

static inline unsigned long
kvm_set_csr_gintc(unsigned long set)
{
	unsigned long res, new;

	res = kvm_read_csr_gintc();
	new = res | set;
	kvm_write_csr_gintc(new);

	return res;
}

static inline unsigned long
kvm_set_gcsr_llbctl(unsigned long set)
{
	unsigned long res, new;

	res = kvm_read_gcsr_llbctl();
	new = res | set;
	kvm_write_gcsr_llbctl(new);

	return res;
}


static inline unsigned long
kvm_clear_csr_gtlbc(unsigned long clear)
{
	unsigned long res, new;

	res = kvm_read_csr_gtlbc();
	new = res & ~clear;
	kvm_write_csr_gtlbc(new);

	return res;
}

static inline unsigned long
kvm_clear_csr_euen(unsigned long clear)
{
	unsigned long res, new;

	res = kvm_read_csr_euen();
	new = res & ~clear;
	kvm_write_csr_euen(new);

	return res;
}

static inline unsigned long
kvm_clear_csr_gintc(unsigned long clear)
{
	unsigned long res, new;

	res = kvm_read_csr_gintc();
	new = res & ~clear;
	kvm_write_csr_gintc(new);

	return res;
}

static inline unsigned long
kvm_change_csr_gstat(unsigned long change, unsigned long val)
{
	unsigned long res, new;

	res = kvm_read_csr_gstat();
	new = res & ~change;
	new |= (val & change);
	kvm_write_csr_gstat(new);

	return res;
}

static inline unsigned long
kvm_change_csr_gcfg(unsigned long change, unsigned long val)
{
	unsigned long res, new;

	res = kvm_read_csr_gcfg();
	new = res & ~change;
	new |= (val & change);
	kvm_write_csr_gcfg(new);

	return res;
}


#define kvm_set_gcsr_estat(val)	\
	kvm_gcsr_xchg(val, val, KVM_CSR_ESTAT)
#define kvm_clear_gcsr_estat(val)	\
	kvm_gcsr_xchg(~(val), val, KVM_CSR_ESTAT)

#endif

/* Device Control API on vcpu fd */
#define KVM_LARCH_VCPU_PVTIME_CTRL  2
#define KVM_LARCH_VCPU_PVTIME_IPA   0

#if (_LOONGARCH_SZLONG == 32)
#define KVM_LONG_ADD	add.w
#define KVM_LONG_ADDI	addi.w
#define KVM_LONG_SUB	sub.w
#define KVM_LONG_L	ld.w
#define KVM_LONG_S	st.w
#define KVM_LONG_SLL	slli.w
#define KVM_LONG_SLLV	sll.w
#define KVM_LONG_SRL	srli.w
#define KVM_LONG_SRLV	srl.w
#define KVM_LONG_SRA	srai.w
#define KVM_LONG_SRAV	sra.w

#define KVM_LONGSIZE	4
#define KVM_LONGMASK	3
#define KVM_LONGLOG	2

/*
 * How to add/sub/load/store/shift pointers.
 */

#define KVM_PTR_ADD	add.w
#define KVM_PTR_ADDI	addi.w
#define KVM_PTR_SUB	sub.w
#define KVM_PTR_L	ld.w
#define KVM_PTR_S	st.w
#define KVM_PTR_LI	li.w
#define KVM_PTR_SLL	slli.w
#define KVM_PTR_SLLV	sll.w
#define KVM_PTR_SRL	srli.w
#define KVM_PTR_SRLV	srl.w
#define KVM_PTR_SRA	srai.w
#define KVM_PTR_SRAV	sra.w

#define KVM_PTR_SCALESHIFT	2

#define KVM_PTRSIZE	4
#define KVM_PTRLOG	2

#endif

#if (_LOONGARCH_SZLONG == 64)
#define KVM_LONG_ADD	add.d
#define KVM_LONG_ADDI	addi.d
#define KVM_LONG_SUB	sub.d
#define KVM_LONG_L	ld.d
#define KVM_LONG_S	st.d
#define KVM_LONG_SLL	slli.d
#define KVM_LONG_SLLV	sll.d
#define KVM_LONG_SRL	srli.d
#define KVM_LONG_SRLV	srl.d
#define KVM_LONG_SRA	sra.w
#define KVM_LONG_SRAV	sra.d

#define KVM_LONGSIZE	8
#define KVM_LONGMASK	7
#define KVM_LONGLOG	3

/*
 * How to add/sub/load/store/shift pointers.
 */

#define KVM_PTR_ADD	add.d
#define KVM_PTR_ADDI	addi.d
#define KVM_PTR_SUB	sub.d
#define KVM_PTR_L	ld.d
#define KVM_PTR_S	st.d
#define KVM_PTR_LI	li.d
#define KVM_PTR_SLL	slli.d
#define KVM_PTR_SLLV	sll.d
#define KVM_PTR_SRL	srli.d
#define KVM_PTR_SRLV	srl.d
#define KVM_PTR_SRA	srai.d
#define KVM_PTR_SRAV	sra.d

#define KVM_PTR_SCALESHIFT	3

#define KVM_PTRSIZE	8
#define KVM_PTRLOG	3
#endif

#endif		/* __LOONGARCH_KVM_COMPAT_H__ */
