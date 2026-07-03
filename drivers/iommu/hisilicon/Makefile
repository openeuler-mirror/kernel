# SPDX-License-Identifier: GPL-2.0+

obj-y += ummu-core/

obj-$(CONFIG_UB_UMMU_BASE) += ummu_ext.o

obj-$(CONFIG_UB_UMMU) += ummu.o
ummu-y := ummu_main.o \
	  queue.o \
	  interrupt.o \
	  page_table.o \
	  cfg_table.o \
	  flush.o  \
	  seg_tree.o \
	  seg_mng.o \
	  ummu_impl.o \
	  ummu_cfg_v1.o \
	  perm_table.o \
	  perm_table.o \
	  perm_queue.o \
	  attribute.o \
	  qos.o \
	  logic_ummu/logic_ummu.o \
	  iommu.o \
	  nested.o \
	  trace.o

ummu-$(CONFIG_UB_UMMU_SVA) += sva.o
ummu-$(CONFIG_UB_UBMEM_UMMU) += ubmem-mmu/ubmem_mmu.o

obj-$(CONFIG_UB_UBMEM_VMMU) += ubmem-mmu/

# for tracing framework to find trace.h
CFLAGS_trace.o := -I$(src)
