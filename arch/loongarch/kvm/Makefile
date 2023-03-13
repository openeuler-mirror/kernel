# SPDX-License-Identifier: GPL-2.0
# Makefile for KVM support for LoongArch
#

OBJECT_FILES_NON_STANDARD_entry.o	:= y

common-objs-y = $(addprefix ../../../virt/kvm/, kvm_main.o coalesced_mmio.o \
				irqchip.o eventfd.o)

KVM := ../../../virt/kvm
common-objs-$(CONFIG_KVM_VFIO) += $(KVM)/vfio.o

EXTRA_CFLAGS += -Ivirt/kvm -Iarch/loongarch/kvm

kvm-objs := $(common-objs-y) loongarch.o emulate.o interrupt.o
kvm-objs += hypcall.o
kvm-objs += mmu.o
kvm-objs += kvm_compat.o

kvm-objs		+= exit.o intc/ls7a_irq.o intc/ls3a_ipi.o intc/irqchip-debug.o\
				timer.o intc/ls3a_ext_irq.o irqfd.o csr.o
obj-$(CONFIG_KVM)	+= kvm.o
obj-y			+= entry.o fpu.o
