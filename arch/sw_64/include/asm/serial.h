/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_SERIAL_H
#define _ASM_SW64_SERIAL_H

#define BASE_BAUD (1843200 / 16)

/* Standard COM flags (except for COM4, because of the 8514 problem) */
#ifdef CONFIG_SERIAL_8250_DETECT_IRQ
#define STD_COM_FLAGS (UPF_BOOT_AUTOCONF | UPF_SKIP_TEST | UPF_AUTO_IRQ)
#define STD_COM4_FLAGS (UPF_BOOT_AUTOCONF | UPF_AUTO_IRQ)
#else
#define STD_COM_FLAGS (UPF_BOOT_AUTOCONF | UPF_SKIP_TEST)
#define STD_COM4_FLAGS UPF_BOOT_AUTOCONF
#endif

#endif /* _ASM_SW64_SERIAL_H */
