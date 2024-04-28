# SPDX-License-Identifier: GPL-2.0
#
# Makefile for Kernel-based Virtual Machine module
#

ccflags-y += -I $(srctree)/$(src)

KVM=../../../virt/kvm

obj-$(CONFIG_KVM) += kvm.o
obj-$(CONFIG_KVM) += hyp/

kvm-y := $(KVM)/kvm_main.o $(KVM)/coalesced_mmio.o $(KVM)/eventfd.o \
	 $(KVM)/vfio.o $(KVM)/irqchip.o \
	 arm.o mmu.o mmio.o psci.o perf.o hypercalls.o pvtime.o pvsched.o \
	 inject_fault.o regmap.o va_layout.o handle_exit.o \
	 guest.o debug.o reset.o sys_regs.o \
	 vgic-sys-reg-v3.o fpsimd.o pmu.o \
	 aarch32.o arch_timer.o trng.o\
	 vgic/vgic.o vgic/vgic-init.o \
	 vgic/vgic-irqfd.o vgic/vgic-v2.o \
	 vgic/vgic-v3.o vgic/vgic-v4.o \
	 vgic/vgic-mmio.o vgic/vgic-mmio-v2.o \
	 vgic/vgic-mmio-v3.o vgic/vgic-kvm-device.o \
	 vgic/vgic-its.o vgic/shadow_dev.o vgic/vgic-debug.o

kvm-$(CONFIG_CVM_HOST)	+= tmi.o
kvm-$(CONFIG_CVM_HOST)	+= cvm.o
kvm-$(CONFIG_CVM_HOST)	+= cvm_exit.o

kvm-$(CONFIG_KVM_ARM_PMU)  += pmu-emul.o
obj-$(CONFIG_KVM_HISI_VIRT) += hisilicon/
