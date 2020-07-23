/*
 * internal.h - printk internal definitions
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include <linux/percpu.h>

#ifdef CONFIG_PRINTK

#define PRINTK_SAFE_CONTEXT_MASK	 0x3fffffff
#define PRINTK_NMI_DIRECT_CONTEXT_MASK	 0x40000000
#define PRINTK_NMI_CONTEXT_MASK		 0x80000000

extern raw_spinlock_t logbuf_lock;

__printf(5, 0)
int vprintk_store(int facility, int level,
		  const char *dict, size_t dictlen,
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
