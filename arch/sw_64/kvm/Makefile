# SPDX-License-Identifier: GPL-2.0
#
# Makefile for Kernel-based Virtual Machine module
#

KVM := ../../../virt/kvm

ccflags-y += -Ivirt/kvm -Iarch/sw_64/kvm

kvm-$(CONFIG_KVM_SW64_HOST) += $(KVM)/kvm_main.o $(KVM)/eventfd.o $(KVM)/irqchip.o $(KVM)/vfio.o
kvm-$(CONFIG_KVM_SW64_HOST) += kvm-sw64.o entry.o emulate.o mmio.o kvm_timer.o handle_exit.o perf.o

obj-$(CONFIG_KVM_SW64_HOST) += kvm.o
