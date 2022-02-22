/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Sigreturn trampoline for returning from a signal when the SA_RESTORER
 * flag is not set.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <linux/linkage.h>
#include <asm/unistd.h>

	.text

ENTRY(__vdso_rt_sigreturn)
	mov		$sp, $16
	ldi		$0, __NR_rt_sigreturn
	sys_call	0x83
ENDPROC(__vdso_rt_sigreturn)
