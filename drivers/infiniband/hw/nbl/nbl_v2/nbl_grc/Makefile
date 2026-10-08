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
        KERNEL_RELEASE = 5.14.21-2-bootis
endif

snic:
	make -C /usr/src/linux-headers-$(KERNEL_RELEASE)/ M=$(shell pwd) modules -j
clean:
	make -C /usr/src/linux-headers-$(KERNEL_RELEASE)/ M=$(shell pwd) clean
upload:
#e.g: make upload user=louis.li
	../.ci/upload.sh $(user)