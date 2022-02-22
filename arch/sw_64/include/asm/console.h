/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_CONSOLE_H
#define _ASM_SW64_CONSOLE_H

#include <uapi/asm/console.h>
#ifndef __ASSEMBLY__
struct crb_struct;
extern int callback_init_done;
extern void callback_init(void);
#endif /* __ASSEMBLY__ */
#endif /* _ASM_SW64_CONSOLE_H */
