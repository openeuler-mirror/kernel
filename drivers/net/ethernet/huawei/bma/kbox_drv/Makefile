obj-$(CONFIG_BMA) += host_kbox_drv.o
host_kbox_drv-y := kbox_main.o kbox_ram_drive.o kbox_ram_image.o kbox_ram_op.o kbox_printk.o kbox_dump.o kbox_hook.o kbox_panic.o
ifdef CONFIG_X86
host_kbox_drv-y += kbox_mce.o
endif