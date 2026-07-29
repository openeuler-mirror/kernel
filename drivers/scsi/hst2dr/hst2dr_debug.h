/* SPDX-License-Identifier: GPL-2.0 */
/*
 * This is the  hst2dr base driver providing common API layer interface
 * for access to hst2dr firmware.
 *
 * This code is based on drivers/scsi/hst2dr/hst2dr_base.h

 * Copyright (c) 2021-2026 Sage Micro Corporation
 * (mailto: driver@sage-micro.com.cn)
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
 * NO WARRANTY
 * THE PROGRAM IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED INCLUDING, WITHOUT
 * LIMITATION, ANY WARRANTIES OR CONDITIONS OF TITLE, NON-INFRINGEMENT,
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE. Each Recipient is
 * solely responsible for determining the appropriateness of using and
 * distributing the Program and assumes all risks associated with its
 * exercise of rights under this Agreement, including but not limited to
 * the risks and costs of program errors, damage to or loss of data,
 * programs or equipment, and unavailability or interruption of operations.

 * DISCLAIMER OF LIABILITY
 * NEITHER RECIPIENT NOR ANY CONTRIBUTORS SHALL HAVE ANY LIABILITY FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING WITHOUT LIMITATION LOST PROFITS), HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OR DISTRIBUTION OF THE PROGRAM OR THE EXERCISE OF ANY RIGHTS GRANTED
 * HEREUNDER, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES

 */

#ifndef HST2DR_DEBUG_H_INCLUDED
#define HST2DR_DEBUG_H_INCLUDED

#define LOG_DEBUG	0x1	// debug info
#define LOG_EVENT	0x2	// asychronize event
#define LOG_INIT	0x4	// initialize
#define LOG_EXIT	0x8	// un-initialize
#define LOG_FAIL	0x10	// error handle
#define LOG_TM		0x20	// task manager
#define LOG_CONFIG	0x40	// config
#define LOG_RESET	0x100
#define LOG_SCSI	0x200
#define LOG_CTRL	0x400
#define LOG_TRANSPORT	0x1000
#define LOG_HAL		0x2000
#define LOG_DEBUG_REPLY 0x4000
#define LOG_COMM	0x100000

#define LOG_ALL		0xFFFFFFFF
#define LOG_OFF		0x0

#define LOG_DEFAULT	(LOG_FAIL | LOG_INIT | LOG_EXIT)

#define HST2DR_LOG

// the log level, only three levels for our driver
#define err_str "ERR"
#define wrn_str "WRN"
#define inf_str "INF"

#define log_always(ioa, fmt, ...) \
		pr_info("%s %s: " fmt, ioa->name, inf_str, ##__VA_ARGS__)

#define log_error(ioa, fmt, ...) \
		pr_err("%s %s: " fmt, ioa->name, err_str, ##__VA_ARGS__)

#define log_warn(ioa, fmt, ...) \
		pr_warn("%s %s: " fmt, ioa->name, wrn_str,  ##__VA_ARGS__)

#ifdef HST2DR_LOG
#define log_type_output(ioa, type, fmt, ...) \
	do { \
		if (ioa->log_level & type) \
			pr_info("%s %s: " fmt, ioa->name, inf_str, ##__VA_ARGS__); \
	} while (0)

#define log_comm(ioa, fmt, ...) \
	log_type_output(ioa, LOG_COMM, fmt, ##__VA_ARGS__)

#define log_debug(ioa, fmt, ...)		\
	log_type_output(ioa, LOG_DEBUG, fmt, ##__VA_ARGS__)

#define log_event(ioa, fmt, ...)			\
	log_type_output(ioa, LOG_EVENT, fmt, ##__VA_ARGS__)

#define log_init(ioa, fmt, ...)			\
	log_type_output(ioa, LOG_INIT, fmt, ##__VA_ARGS__)

#define log_exit(ioa, fmt, ...)			\
	log_type_output(ioa, LOG_EXIT, fmt, ##__VA_ARGS__)

#define log_fail(ioa, fmt, ...)			\
	log_type_output(ioa, LOG_FAIL, fmt, ##__VA_ARGS__)

#define log_tm(ioa, fmt, ...)			\
	log_type_output(ioa, LOG_TM, fmt, ##__VA_ARGS__)

#define log_config(ioa, fmt, ...)			\
	log_type_output(ioa, LOG_CONFIG, fmt, ##__VA_ARGS__)

#define log_reset(ioa, fmt, ...)			\
	log_type_output(ioa, LOG_RESET, fmt, ##__VA_ARGS__)

#define log_scsi(ioa, fmt, ...)			\
	log_type_output(ioa, LOG_SCSI, fmt, ##__VA_ARGS__)

#define log_ctrl(ioa, fmt, ...)			\
	log_type_output(ioa, LOG_CTRL, fmt, ##__VA_ARGS__)

#define log_transport(ioa, fmt, ...)		\
	log_type_output(ioa, LOG_TRANSPORT, fmt, ##__VA_ARGS__)

#define log_hal(ioa, fmt, ...)			\
	log_type_output(ioa, LOG_HAL, fmt, ##__VA_ARGS__)

#define log_set_all(ioa)	(ioa->log_level |= LOG_ALL)

#define debug_dump_mem(a, b, c) \
	do { \
		if (ioa->log_level & LOG_DEBUG) \
			_debug_dump_mem(a, b, c); \
	} while (0)
#else
#define log_type_output(ioa, type, fmt, ...)
#define log_debug(ioa, fmt, ...)
#define log_event(ioa, fmt, ...)
#define log_init(ioa, fmt, ...)
#define log_exit(ioa, fmt, ...)
#define log_fail(ioa, fmt, ...)
#define log_tm(ioa, fmt, ...)
#define log_config(ioa, fmt, ...)
#define log_reset(ioa, fmt, ...)
#define log_scsi(ioa, fmt, ...)
#define log_ctrl(ioa, fmt, ...)
#define log_transport(ioa, fmt, ...)
#define log_hal(ioa, fmt, ...)
#define log_set_all(ioa)
#define debug_dump_mem(a, b, c)

#endif // End of HST2DR_LOG

extern int hst2dr_debug_intr;

enum hst2dr_intr_debug {
	SSI2_INTR_MSIX_ENABLE,			// usi msix first, if msix is not supportted, use legacy
	SSI2_INTR_MSIX_DISABLE,			// Force to use legacy
	SSI2_INTR_MSIX_NORMAL_TO_LEGACY,	// request msix, also legacy
	SSI2_INTR_MSIX_NORMAL_FREE_TO_LEGACY,	// request msix but free it, then use legacy
	SSI2_INTR_MSIX_FAIL_TO_LEGACY		// request msix, let it fail. then auto switch to legacy
};

#endif

