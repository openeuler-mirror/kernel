/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * internal.h - printk internal definitions
 */
#include <linux/percpu.h>

#ifdef CONFIG_PRINTK

#define PRINTK_SAFE_CONTEXT_MASK	0x007ffffff
#define PRINTK_NMI_DIRECT_CONTEXT_MASK	0x008000000
#define PRINTK_NMI_CONTEXT_MASK		0xff0000000

#define PRINTK_NMI_CONTEXT_OFFSET	0x010000000

extern raw_spinlock_t logbuf_lock;

__printf(4, 0)
int vprintk_store(int facility, int level,
		  const struct dev_printk_info *dev_info,
		  const char *fmt, va_list args);

__printf(1, 0) int vprintk_default(const char *fmt, va_list args);
__printf(1, 0) int vprintk_deferred(const char *fmt, va_list args);
__printf(1, 0) int vprintk_func(const char *fmt, va_list args);

void printk_safe_init(void);
bool printk_percpu_data_ready(void);

void defer_console_output(void);

#else

__printf(1, 0) int vprintk_func(const char *fmt, va_list args) { return 0; }

static inline void printk_safe_init(void) { }
static inline bool printk_percpu_data_ready(void) { return false; }
#endif /* CONFIG_PRINTK */
