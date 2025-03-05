# SPDX-License-Identifier: GPL-2.0
#
# Makefile for Kernel-based Virtual Machine module
#

KVM := ../../../virt/kvm

ccflags-y += -Ivirt/kvm -Iarch/sw_64/kvm

obj-$(CONFIG_KVM) += kvm.o

kvm-y := $(KVM)/kvm_main.o $(KVM)/eventfd.o $(KVM)/irqchip.o $(KVM)/vfio.o \
	 sw64.o entry.o emulate.o mmio.o kvm_timer.o handle_exit.o perf.o

kvm-$(CONFIG_SUBARCH_C3B) += kvm_core3.o
kvm-$(CONFIG_SUBARCH_C4) += kvm_core4.o mmu.o
