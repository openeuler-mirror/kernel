// SPDX-License-Identifier: GPL-2.0

//! PCI devices and drivers.
//!
//! C header: [`include/linux/pci.h`](../../../../include/linux/pci.h)

use crate::{
    bindings, c_types, device, driver,
    error::{from_kernel_result, Result},
    str::CStr,
    to_result,
    types::PointerWrapper,
    ThisModule,
};

/// An adapter for the registration of PCI drivers.
pub struct Adapter<T: Driver>(T);

impl<T: Driver> driver::DriverOps for Adapter<T> {
    type RegType = bindings::pci_driver;

    unsafe fn register(
        reg: *mut bindings::pci_driver,
        name: &'static CStr,
        module: &'static ThisModule,
    ) -> Result {
        let pdrv: &mut bindings::pci_driver = unsafe { &mut *reg };

        pdrv.name = name.as_char_ptr();
        pdrv.probe = Some(Self::probe_callback);
        pdrv.remove = Some(Self::remove_callback);
        pdrv.id_table = T::PCI_ID_TABLE.as_ptr();
        to_result(|| unsafe { bindings::__pci_register_driver(reg, module.0, name.as_char_ptr()) })
    }

    unsafe fn unregister(reg: *mut bindings::pci_driver) {
        unsafe { bindings::pci_unregister_driver(reg) }
    }
}

impl<T: Driver> Adapter<T> {
    extern "C" fn probe_callback(
        pdev: *mut bindings::pci_dev,
        _id: *const bindings::pci_device_id,
    ) -> c_types::c_int {
        from_kernel_result! {
            let mut dev = unsafe { Device::from_ptr(pdev) };
            let data = T::probe(&mut dev)?;
            unsafe { bindings::pci_set_drvdata(pdev, data.into_pointer() as _) };
            Ok(0)
        }
    }

    extern "C" fn remove_callback(pdev: *mut bindings::pci_dev) {
        let ptr = unsafe { bindings::pci_get_drvdata(pdev) };
        let data = unsafe { T::Data::from_pointer(ptr) };
        T::remove(&data);
        <T::Data as driver::DeviceRemoval>::device_remove(&data);
    }
}

/// A PCI driver
pub trait Driver {
    /// Data stored on device by driver.
    ///
    /// Corresponds to the data set or retrieved via the kernel's
    /// `pci_{set,get}_drvdata()` functions.
    ///
    /// Require that `Data` implements `PointerWrapper`. We guarantee to
    /// never move the underlying wrapped data structure. This allows
    type Data: PointerWrapper + Send + Sync + driver::DeviceRemoval = ();

    /// The table of device ids supported by the driver.
    const PCI_ID_TABLE: &'static [bindings::pci_device_id];

    /// PCI driver probe.
    ///
    /// Called when a new platform device is added or discovered.
    /// Implementers should attempt to initialize the device here.
    fn probe(dev: &mut Device) -> Result<Self::Data>;

    /// PCI driver remove.
    ///
    /// Called when a platform device is removed.
    /// Implementers should prepare the device for complete removal here.
    fn remove(_data: &Self::Data);
}

/// A PCI device.
///
/// # Invariants
///
/// The field `ptr` is non-null and valid for the lifetime of the object.
pub struct Device {
    ptr: *mut bindings::pci_dev,
}

impl Device {
    unsafe fn from_ptr(ptr: *mut bindings::pci_dev) -> Self {
        Self { ptr }
    }
}

unsafe impl device::RawDevice for Device {
    fn raw_device(&self) -> *mut bindings::device {
        // SAFETY: By the type invariants, we know that `self.ptr` is non-null and valid.
        unsafe { &mut (*self.ptr).dev }
    }
}
