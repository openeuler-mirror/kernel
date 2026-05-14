# SPDX-License-Identifier: GPL-2.0+

obj-$(CONFIG_UB_UBUS) += ub-driver.o controller.o config.o entity.o ras.o
obj-$(CONFIG_UB_UBUS) += msi/

ubus-y := ubus_driver.o sysfs.o ubus_controller.o msg.o ubus_config.o port.o cc.o eid.o cna.o route.o
ubus-y += enum.o resource.o ubus_entity.o reset.o cap.o interrupt.o decoder.o ioctl.o eu.o link.o
ubus-y += instance.o pool.o memory.o ub_black_box.o task.o

ubus-y += services/ras.o services/service.o services/gucd.o
ubus-y += services/hotplug/hotplug_core.o services/hotplug/hotplug_ctrl.o
ubus-y += services/hotplug/hotplug_route.o services/hotplug/hotplug_msg.o

obj-$(CONFIG_UB_UBUS_BUS) += ubus.o
obj-y += vendor/
