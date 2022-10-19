// SPDX-License-Identifier: GPL-2.0

//! Broadcom CAVIUM Random Number Generator support.

use kernel::{
    bindings, define_pci_id_table, device, file, file::File, io_buffer::IoBufferWriter,
    io_mem::IoMem, miscdev, module_pci_driver, pci, prelude::*, sync::Ref,
};

module_pci_driver! {
    type: RngDriver,
    name: b"cavium_rng_rust",
    author: b"Rust for Linux Contributors",
    description: b"Cavium Random Number Generator (RNG) driver",
    license: b"GPL v2",
}

const THUNDERX_RNM_ENT_EN: u64 = 0x1;
const THUNDERX_RNM_RNG_EN: u64 = 0x2;
const CAVIUM_SIZE: usize = 0x1000;

struct RngDevice;

impl file::Operations for RngDevice {
    kernel::declare_file_operations!();

    fn open(_open_data: &(), _file: &File) -> Result {
        Ok(())
    }

    fn read(_: (), _: &File, data: &mut impl IoBufferWriter, offset: u64) -> Result<usize> {
        // Succeed if the caller doesn't provide a buffer or if not at the start.
        if data.is_empty() || offset != 0 {
            return Ok(0);
        }

        data.write(&0_u32)?;
        Ok(4)
    }
}

struct CAVIUMResources {
    base: IoMem<CAVIUM_SIZE>,
}

struct CAVIUMData {
    dev: device::Device,
}

type DeviceData = device::Data<miscdev::Registration<RngDevice>, CAVIUMResources, CAVIUMData>;

struct RngDriver;
impl pci::Driver for RngDriver {
    type Data = Ref<DeviceData>;

    define_pci_id_table! {u32, [
        (pci::DeviceId::new(bindings::PCI_VENDOR_ID_CAVIUM, 0xa018), None),
    ]}

    fn probe(dev: &mut pci::Device, _id_info: Option<&Self::IdInfo>) -> Result<Self::Data> {
        let res = dev.take_resource().ok_or(ENXIO)?;

        let res = CAVIUMResources {
            // SAFETY: This device doesn't support DMA.
            base: unsafe { IoMem::try_new(res)? },
        };
        res.base
            .writeq(THUNDERX_RNM_ENT_EN | THUNDERX_RNM_RNG_EN, 0);

        let ret = dev.pci_enable_sriov(1);
        match ret {
            Ok(_o) => (),
            Err(_e) => {
                dev_err!(dev, "Error initializing RNG virtual function.\n",);
                res.base.writeq(0, 0);
                return Err(_e);
            }
        }

        let cdata = CAVIUMData {
            dev: device::Device::from_dev(dev),
        };

        let mut data = kernel::new_device_data!(
            miscdev::Registration::new(),
            res,
            cdata,
            "CAVIUM::Registrations"
        )?;

        let data = Ref::<DeviceData>::from(data);

        data.registrations()
            .ok_or(ENXIO)?
            .as_pinned_mut()
            .register(fmt!("rust_cavium"), ())?;

        Ok(data.into())
    }
}
