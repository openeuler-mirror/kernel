/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_CURRENT_H
#define _ASM_SW64_CURRENT_H

#include <linux/thread_info.h>

#define get_current()	(current_thread_info()->task)
#define current		get_current()

#endif /* _ASM_SW64_CURRENT_H */
