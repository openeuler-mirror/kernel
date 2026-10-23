obj-m := nbl_grc.o
nbl_grc-objs := grc_main.o   \
		grc_mailbox.o \
		grc_hw_rdma.o \
		grc_cqp.o \
		grc_gid.o \
		grc_counters.o
ccflags-y:=  -g

ccflags-y += -I$(src)/../nbl_include/
ifndef KERNEL_RELEASE
        KERNEL_RELEASE = $(shell uname -r)
endif

ifndef KERNEL_PATH
	KERNEL_PATH = /usr/src/linux-headers-$(KERNEL_RELEASE)
endif

ifneq ($(findstring ky10,$(KERNELVERSION)),)
ccflags-y += -DKYLINV10
endif

ifeq ($(WITH_OFED), 1)
OFA_DIR = /usr/src/ofa_kernel/default
endif

ifneq (${OFA_DIR},)
ifneq ($(shell test -d $(OFA_DIR) && echo "true" || echo ""),)
ccflags-y += -DOFED_BUILD
OFAINCLUDE= -I$(OFA_DIR)/include
LINUXINCLUDE := ${OFAINCLUDE}\
				${LINUXINCLUDE}
KBUILD_EXTRA_SYMBOLS=$(OFA_DIR)/Module.symvers
endif
endif

snic:
	make -C $(KERNEL_PATH) M=$(shell pwd) modules -j
clean:
	make -C $(KERNEL_PATH) M=$(shell pwd) clean
upload:
#e.g: make upload user=louis.li
	../.ci/upload.sh $(user)