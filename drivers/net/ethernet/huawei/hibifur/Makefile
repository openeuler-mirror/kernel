EXPORT_SYMBOL := true

KBUILD_EXTRA_SYMBOLS += $(srctree)/drivers/net/ethernet/huawei/hinic3/Module.symvers

ccflags-y += -I$(srctree)/include/linux
ccflags-y += -I$(srctree)/drivers/net/ethernet/huawei/hinic3/include/public
ccflags-y += -I$(srctree)/drivers/net/ethernet/huawei/hinic3/include/cfg_mgmt
ccflags-y += -I$(srctree)/drivers/net/ethernet/huawei/hinic3/include/cqm
ccflags-y += -I$(srctree)/drivers/net/ethernet/huawei/hinic3/include/bond
ccflags-y += -I$(srctree)/drivers/net/ethernet/huawei/hinic3/include/mpu
ccflags-y += -I$(srctree)/drivers/net/ethernet/huawei/hinic3/hw
ccflags-y += -I$(srctree)/drivers/net/ethernet/huawei/hinic3/bond
ccflags-y += -I$(srctree)/drivers/net/ethernet/huawei/hibifur/include
ccflags-y += -I$(srctree)/drivers/net/ethernet/huawei/hibifur/include/nic
ccflags-y += -I$(srctree)/drivers/net/ethernet/huawei/hinic3
ccflags-y += -I$(srctree)/drivers/net/ethernet/huawei/hinic3/include

obj-$(CONFIG_HIBIFUR) += hibifur3.o

hibifur3-objs := bifur_main.o \
            bifur_vf_mgr.o \
            bifur_pfile.o \
            bifur_event.o
