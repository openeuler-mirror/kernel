// SPDX-License-Identifier: GPL-2.0
/*
 *  loongson_generic_laptop.c - Loongson processor
 *  				based LAPTOP/ALL-IN-ONE driver
 *
 *  lvjianmin <lvjianmin@loongson.cn>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#define LSACPI_VERSION "1.0"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/platform_device.h>
#include <linux/input.h>
#include <linux/acpi.h>
#include <acpi/video.h>
#include <linux/pci.h>
#include <linux/uaccess.h>
#include <linux/input/sparse-keymap.h>
#include <linux/device.h>
#include <linux/backlight.h>

/* ACPI HIDs */
#define ACPI_LOONGSON_HKEY_HID	"LOON0000"
#define ACPI_EC_HID		"PNP0C09"

/****************************************************************************
 * Main driver
 */

#define LSACPI_NAME "loongson-laptop"
#define LSACPI_DESC "Loongson Laptop/all-in-one ACPI Driver"
#define LSACPI_FILE LSACPI_NAME "_acpi"
#define LSACPI_DRVR_NAME LSACPI_FILE
#define LSACPI_ACPI_EVENT_PREFIX "loongson_generic"
/****************************************************************************
 * Driver-wide structs and misc. variables
 */

struct generic_sub_driver {
	u32 type;
	char *name;
	acpi_handle *handle;
	struct acpi_device *device;
	struct platform_driver *driver;
	int (*init)(struct generic_sub_driver *sub_driver);
	void (*notify)(struct generic_sub_driver *sub_driver, u32 event);
	u8 acpi_notify_installed;
};

static u32 input_device_registered;

static int hotkey_status_get(int *status);

static int loongson_laptop_backlight_update(struct backlight_device *bd);
/****************************************************************************
 ****************************************************************************
 *
 * ACPI Helpers and device model
 *
 ****************************************************************************
 ****************************************************************************/

/*************************************************************************
 * ACPI basic handles
 */

static int acpi_evalf(acpi_handle handle,
		      int *res, char *method, char *fmt, ...);
static acpi_handle hkey_handle;

static void dispatch_acpi_notify(acpi_handle handle, u32 event, void *data)
{
	struct generic_sub_driver *sub_driver = data;

	if (!sub_driver || !sub_driver->notify)
		return;
	sub_driver->notify(sub_driver, event);
}

static int __init setup_acpi_notify(struct generic_sub_driver *sub_driver)
{
	acpi_status status;
	int rc;

	if (!*sub_driver->handle)
		return 0;

	rc = acpi_bus_get_device(*sub_driver->handle, &sub_driver->device);
	if (rc < 0) {
		pr_err("acpi_bus_get_device(%s) failed: %d\n",
				sub_driver->name, rc);
		return -ENODEV;
	}

	sub_driver->device->driver_data = sub_driver;
	sprintf(acpi_device_class(sub_driver->device), "%s/%s",
		LSACPI_ACPI_EVENT_PREFIX, sub_driver->name);

	status = acpi_install_notify_handler(*sub_driver->handle,
			sub_driver->type, dispatch_acpi_notify, sub_driver);
	if (ACPI_FAILURE(status)) {
		if (status == AE_ALREADY_EXISTS) {
			pr_notice("another device driver is already "
				  "handling %s events\n", sub_driver->name);
		} else {
			pr_err("acpi_install_notify_handler(%s) failed: %s\n",
			       sub_driver->name, acpi_format_exception(status));
		}
		return -ENODEV;
	}
	sub_driver->acpi_notify_installed = 1;
	return 0;
}

static struct input_dev *generic_inputdev;

#ifdef CONFIG_PM
static int loongson_hkey_suspend(struct device *dev)
{
	return 0;
}
static int loongson_hkey_resume(struct device *dev)
{
	int status = 0;
	struct key_entry ke;

	struct backlight_device *bd;
	bd = backlight_device_get_by_type(BACKLIGHT_PLATFORM);
	if (bd) {
		loongson_laptop_backlight_update(bd) ?
		pr_warn("Loongson_backlight:resume brightness failed") :
		pr_info("Loongson_backlight:resume brightness %d\n", bd->props.brightness);
	}
	/*
	 * Only if the firmware supports SW_LID event model, we can handle the
	 * event. This is for the consideration of development board without
	 * EC.
	 */
	if (test_bit(SW_LID, generic_inputdev->swbit)) {
		if (hotkey_status_get(&status))
			return -EIO;
		/*
		 * The input device sw element records the last lid status.
		 * When the system is awakened by other wake-up sources,
		 * the lid event will also be reported. The judgment of
		 * adding SW_LID bit which in sw element can avoid this
		 * case.
		 *
		 * input system will drop lid event when current lid event
		 * value and last lid status in the same data set，which
		 * data set inclue zero set and no zero set. so laptop
		 * driver doesn't report repeated events.
		 *
		 * Lid status is generally 0, but hardware exception is
		 * considered. So add lid status confirmation.
		 */
		if (test_bit(SW_LID, generic_inputdev->sw) && !(status & (1 << SW_LID))) {
			ke.type = KE_SW;
			ke.sw.value = (u8)status;
			ke.sw.code = SW_LID;
			sparse_keymap_report_entry(generic_inputdev, &ke,
					1, true);
		}
	}

	return 0;
}

static const struct dev_pm_ops loongson_hkey_dev_pm_ops = {
	.suspend_noirq	= loongson_hkey_suspend,
	.resume		= loongson_hkey_resume,
};

#define LOONGSON_HKEY_DEV_PM_OPS (&loongson_hkey_dev_pm_ops)
#else
#define LOONGSON_HKEY_DEV_PM_OPS NULL
#endif
static int loongson_hkey_probe(struct platform_device *pdev)
{
	hkey_handle = ACPI_HANDLE(&pdev->dev);

	if (!hkey_handle)
		return -ENODEV;

	return 0;
}

static const struct acpi_device_id loongson_htk_device_ids[] = {
	{ACPI_LOONGSON_HKEY_HID, 0},
	{"", 0},
};

static struct platform_driver loongson_hkey_driver = {
	.probe		= loongson_hkey_probe,
	.driver		= {
		.name	= "loongson-hkey",
		.owner	= THIS_MODULE,
		.pm	= LOONGSON_HKEY_DEV_PM_OPS,
		.acpi_match_table = ACPI_PTR(loongson_htk_device_ids),
	},
};

/*
 * Loongson generic laptop firmware event model
 *
 */

#define GENERIC_HOTKEY_MAP_MAX	64
#define METHOD_NAME__KMAP	"KMAP"
static struct key_entry hotkey_keycode_map[GENERIC_HOTKEY_MAP_MAX];
static int hkey_map(void)
{
	struct acpi_buffer buf;
	union acpi_object *pack;
	acpi_status status;
	u32 index;

	buf.length = ACPI_ALLOCATE_BUFFER;
	status = acpi_evaluate_object_typed(hkey_handle,
			METHOD_NAME__KMAP, NULL, &buf, ACPI_TYPE_PACKAGE);
	if (status != AE_OK) {
		printk(KERN_ERR ": ACPI exception: %s\n",
				acpi_format_exception(status));
		return -1;
	}
	pack = buf.pointer;
	for (index = 0; index < pack->package.count; index++) {
		union acpi_object *sub_pack = &pack->package.elements[index];
		union acpi_object *element = &sub_pack->package.elements[0];

		hotkey_keycode_map[index].type = element->integer.value;
		element = &sub_pack->package.elements[1];
		hotkey_keycode_map[index].code = element->integer.value;
		element = &sub_pack->package.elements[2];
		hotkey_keycode_map[index].keycode = element->integer.value;
	}
	return 0;
}

static int hotkey_backlight_set(bool enable)
{
	if (!acpi_evalf(hkey_handle, NULL, "VCBL", "vd", enable ? 1 : 0))
		return -EIO;

	return 0;
}
static int event_init(struct generic_sub_driver *sub_driver)
{
	int ret;

	ret = hkey_map();
	if (ret) {
		printk(KERN_ERR "Fail to parse keymap from DSDT.\n");
		return ret;
	}

	ret = sparse_keymap_setup(generic_inputdev, hotkey_keycode_map, NULL);
	if (ret) {
		printk(KERN_ERR "Fail to setup input device keymap\n");
		input_free_device(generic_inputdev);

		return ret;
	}

	/*
	 * This hotkey driver handle backlight event when
	 * acpi_video_get_backlight_type() gets acpi_backlight_vendor
	 */
	if (acpi_video_get_backlight_type() != acpi_backlight_vendor)
		hotkey_backlight_set(false);
	else
		hotkey_backlight_set(true);

	printk("ACPI:enabling firmware HKEY event interface...\n");
	return ret;

}

#define GENERIC_EVENT_TYPE_OFF		12
#define GENERIC_EVENT_MASK		0xFFF
#define TPACPI_MAX_ACPI_ARGS 3
static int acpi_evalf(acpi_handle handle,
		      int *res, char *method, char *fmt, ...)
{
	char *fmt0 = fmt;
	struct acpi_object_list params;
	union acpi_object in_objs[TPACPI_MAX_ACPI_ARGS];
	struct acpi_buffer result, *resultp;
	union acpi_object out_obj;
	acpi_status status;
	va_list ap;
	char res_type;
	int success;
	int quiet;

	if (!*fmt) {
		pr_err("acpi_evalf() called with empty format\n");
		return 0;
	}

	if (*fmt == 'q') {
		quiet = 1;
		fmt++;
	} else
		quiet = 0;

	res_type = *(fmt++);

	params.count = 0;
	params.pointer = &in_objs[0];

	va_start(ap, fmt);
	while (*fmt) {
		char c = *(fmt++);
		switch (c) {
		case 'd':	/* int */
			in_objs[params.count].integer.value = va_arg(ap, int);
			in_objs[params.count++].type = ACPI_TYPE_INTEGER;
			break;
			/* add more types as needed */
		default:
			pr_err("acpi_evalf() called with invalid format character '%c'\n",
			       c);
			va_end(ap);
			return 0;
		}
	}
	va_end(ap);

	if (res_type != 'v') {
		result.length = sizeof(out_obj);
		result.pointer = &out_obj;
		resultp = &result;
	} else
		resultp = NULL;

	status = acpi_evaluate_object(handle, method, &params, resultp);

	switch (res_type) {
	case 'd':		/* int */
		success = (status == AE_OK &&
			   out_obj.type == ACPI_TYPE_INTEGER);
		if (success && res)
			*res = out_obj.integer.value;
		break;
	case 'v':		/* void */
		success = status == AE_OK;
		break;
		/* add more types as needed */
	default:
		pr_err("acpi_evalf() called with invalid format character '%c'\n",
		       res_type);
		return 0;
	}

	if (!success && !quiet)
		pr_err("acpi_evalf(%s, %s, ...) failed: %s\n",
		       method, fmt0, acpi_format_exception(status));

	return success;
}

int ec_get_brightness(void)
{
	int status = 0;

	if (!hkey_handle)
		return -ENXIO;

	if (!acpi_evalf(hkey_handle, &status, "ECBG", "d"))
		return -EIO;

	if (status < 0)
		return status;

	return status;
}
EXPORT_SYMBOL(ec_get_brightness);

int ec_set_brightness(int level)
{

	int ret = 0;
	if (!hkey_handle)
		return -ENXIO;

	if (!acpi_evalf(hkey_handle, NULL, "ECBS", "vd", level))
		ret = -EIO;

	return ret;
}
EXPORT_SYMBOL(ec_set_brightness);

int ec_bl_level(u8 level)
{
	int status = 0;

	if (!hkey_handle)
		return -ENXIO;

	if (!acpi_evalf(hkey_handle, &status, "ECLL", "d"))
		return -EIO;
	if (status < 0 || level > status)
		return status;

	if (!acpi_evalf(hkey_handle, &status, "ECSL", "d"))
		return -EIO;

	if (status < 0 || level < status)
		return status;

	return level;
}
EXPORT_SYMBOL(ec_bl_level);

static int loongson_laptop_backlight_update(struct backlight_device *bd)
{
	int lvl = ec_bl_level(bd->props.brightness);
	if (lvl < 0)
		return -EIO;
	if (ec_set_brightness(lvl))
		return -EIO;
	return 0;
}

static int loongson_laptop_get_brightness(struct backlight_device *bd)
{
	u8 __maybe_unused level;

	level = ec_get_brightness();
	if (level >= 0)
		return level;
	return -EIO;
}

static const struct backlight_ops ls_backlight_laptop_ops = {
	.update_status = loongson_laptop_backlight_update,
	.get_brightness = loongson_laptop_get_brightness,
};

static int ls_laptop_backlight_register(void)
{
	struct backlight_properties props;
	int status = 0;
	memset(&props, 0, sizeof(props));
	props.type = BACKLIGHT_PLATFORM;

	if (!acpi_evalf(hkey_handle, &status, "ECLL", "d"))
		return -EIO;
	props.max_brightness = status;
	props.brightness = 1;

	if (backlight_device_register("loongson_laptop",
				NULL, NULL,
				&ls_backlight_laptop_ops, &props))
		return 0;

	return -EIO;
}

static int hotkey_status_get(int *status)
{
	if (!acpi_evalf(hkey_handle, status, "GSWS", "d"))
		return -EIO;

	return 0;
}
int turn_off_lvds(void)
{
	int status;
	union acpi_object arg0 = { ACPI_TYPE_INTEGER };
	struct acpi_object_list args = { 1, &arg0 };
	arg0.integer.value = 0;
	status = acpi_evaluate_object(NULL, "\\BLSW", &args, NULL);
	if (ACPI_FAILURE(status)) {
		pr_info("Loongson lvds error:0x%x\n", status);
		return -ENODEV;
	}
	return 0;
}

int turn_on_lvds(void)
{
	int status;
	union acpi_object arg0 = { ACPI_TYPE_INTEGER };
	struct acpi_object_list args = { 1, &arg0 };
	arg0.integer.value = 1;
	status = acpi_evaluate_object(NULL, "\\BLSW", &args, NULL);
	if (ACPI_FAILURE(status)) {
		pr_info("Loongson lvds error:0x%x\n", status);
		return -ENODEV;
	}
	return 0;
}
static void event_notify(struct generic_sub_driver *sub_driver, u32 event)
{
	struct key_entry *ke = NULL;
	int scan_code = event & GENERIC_EVENT_MASK;
	int type = (event >> GENERIC_EVENT_TYPE_OFF) & 0xF;

	ke = sparse_keymap_entry_from_scancode(generic_inputdev, scan_code);
	if (ke) {
		if (type == KE_SW) {
			int status = 0;

			if (hotkey_status_get(&status))
				return;
			ke->sw.value = !!(status & (1 << ke->sw.code));
		}
		sparse_keymap_report_entry(generic_inputdev, ke, 1, true);
	}
}

/****************************************************************************
 ****************************************************************************
 *
 * Infrastructure
 *
 ****************************************************************************
 ****************************************************************************/
static void generic_exit(struct generic_sub_driver *sub_driver)
{

	if (sub_driver->acpi_notify_installed) {
		acpi_remove_notify_handler(*sub_driver->handle,
				sub_driver->type, dispatch_acpi_notify);
		sub_driver->acpi_notify_installed = 0;
	}
}

static int __init generic_subdriver_init(struct generic_sub_driver *sub_driver)
{
	int ret;

	if (!sub_driver || !sub_driver->driver)
		return -EINVAL;

	ret = platform_driver_register(sub_driver->driver);
	if (ret)
		return -EINVAL;

	if (sub_driver->init)
		sub_driver->init(sub_driver);

	if (sub_driver->notify) {
		ret = setup_acpi_notify(sub_driver);
		if (ret == -ENODEV) {
			ret = 0;
			goto err_out;
		}
		if (ret < 0)
			goto err_out;
	}

	return 0;

err_out:
	generic_exit(sub_driver);
	return (ret < 0) ? ret : 0;
}

/* Module init, exit, parameters */
static struct generic_sub_driver generic_sub_drivers[] = {
	{
		.name = "hkey",
		.init = event_init,
		.notify = event_notify,
		.handle = &hkey_handle,
		.type = ACPI_DEVICE_NOTIFY,
		.driver = &loongson_hkey_driver,
	},
};

static void generic_acpi_module_exit(void)
{
	if (generic_inputdev) {
		if (input_device_registered)
			input_unregister_device(generic_inputdev);
		else
			input_free_device(generic_inputdev);
	}
}

static int __init generic_acpi_module_init(void)
{
	int ret, i;
	int status;
	bool ec_found;

	if (acpi_disabled)
		return -ENODEV;

	/* The EC device is required */
	ec_found = acpi_dev_found(ACPI_EC_HID);
	if (!ec_found)
		return -ENODEV;

	generic_inputdev = input_allocate_device();
	if (!generic_inputdev) {
		pr_err("unable to allocate input device\n");
		generic_acpi_module_exit();
		return -ENOMEM;
	}

	/* Prepare input device, but don't register */
	generic_inputdev->name =
		"Loongson Generic Laptop/All-in-one Extra Buttons";
	generic_inputdev->phys = LSACPI_DRVR_NAME "/input0";
	generic_inputdev->id.bustype = BUS_HOST;
	generic_inputdev->dev.parent = NULL;

	/* Init subdrivers */
	for (i = 0; i < ARRAY_SIZE(generic_sub_drivers); i++) {
		ret = generic_subdriver_init(&generic_sub_drivers[i]);
		if (ret < 0) {
			generic_acpi_module_exit();
			return ret;
		}
	}

	ret = input_register_device(generic_inputdev);
	if (ret < 0) {
		pr_err("unable to register input device\n");
		generic_acpi_module_exit();
		return ret;
	}

	input_device_registered = 1;

	if (acpi_evalf(hkey_handle, &status, "ECBG", "d")) {
		pr_info("Loongson Laptop used, init brightness is 0x%x\n", status);
		ret = ls_laptop_backlight_register();
		if (ret < 0)
			pr_err("Loongson Laptop:laptop-backlight device register failed\n");
	} else
		pr_info("Loongson Laptop :laptop-backlight device is not in use\n");
	return 0;
}

MODULE_ALIAS("platform:ls-laptop");
MODULE_AUTHOR("lvjianmin <lvjianmin@loongson.cn>");
MODULE_DESCRIPTION(LSACPI_DESC);
MODULE_VERSION(LSACPI_VERSION);
MODULE_LICENSE("GPL");

module_init(generic_acpi_module_init);
module_exit(generic_acpi_module_exit);
