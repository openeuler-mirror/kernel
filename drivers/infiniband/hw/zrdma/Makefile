ccflags-y += -I$(zrdma)
ccflags-y += -I$(zrdma)/smmu/kernel
subdir-ccflags-y += -I$(srctree)/drivers/net/ethernet/dinghai/en_np/table/include
subdir-ccflags-y += -I$(srctree)/drivers/net/ethernet/dinghai/en_np/comm/include
subdir-ccflags-y += -I$(srctree)/drivers/net/ethernet/dinghai/en_np/driver/include
subdir-ccflags-y += -I$(srctree)/drivers/net/ethernet/dinghai/en_np/sdk/include/dev/module/table/se
subdir-ccflags-y += -I$(srctree)/drivers/net/ethernet/dinghai/en_np/sdk/include/dev/module/se
subdir-ccflags-y += -I$(srctree)/drivers/net/ethernet/dinghai/en_np/sdk/include/api
subdir-ccflags-y += -I$(srctree)/drivers/net/ethernet/dinghai/en_np/sdk/include/dev/chip
subdir-ccflags-y += -I$(srctree)/drivers/net/ethernet/dinghai/en_np/sdk/include/dev/reg
subdir-ccflags-y += -I$(srctree)/drivers/net/ethernet/dinghai/en_np/sdk/include/dev/module/dma
subdir-ccflags-y += -I$(srctree)/drivers/net/ethernet/dinghai/en_np/sdk/include/dev/module/nppu
subdir-ccflags-y += -I$(srctree)/drivers/net/ethernet/dinghai/en_np/sdk/include/dev/module/ppu
subdir-ccflags-y += -I$(srctree)/drivers/net/ethernet/dinghai/en_np/sdk/include/dev/module/table
subdir-ccflags-y += -I$(srctree)/drivers/net/ethernet/dinghai/en_np/sdk/include/dev/module/tm
subdir-ccflags-y += -I$(srctree)/drivers/net/ethernet/dinghai/en_np/sdk/include/diag
subdir-ccflags-y += -I$(srctree)/drivers/net/ethernet/dinghai/en_np/agent/include

obj-$(CONFIG_INFINIBAND_ZRDMA) += zrdma.o

zrdma-y := \
	main.o \
	manager.o \
	verbs.o \
	private_verbs_cmd.o \
	ctrl.o \
	hw.o \
	icrdma_hw.o \
	hmc.o \
	pble.o \
	utils.o \
	uk.o \
	dbgfs.o \
	configfs.o \
	cm.o \
	srq.o \
	puda.o \
	uda.o \
	vf.o \
	virtchnl.o \
	restrack.o \
	trace.o \
	tc_hmcdma.o \
	zrdma_kcompat.o \
	smmu/kernel/adk_mmu600.o \
	smmu/kernel/cmdk_mmu600.o \
	smmu/kernel/cmdk_pagetable.o
