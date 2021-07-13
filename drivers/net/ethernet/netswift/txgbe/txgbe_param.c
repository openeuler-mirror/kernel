/*
 * WangXun 10 Gigabit PCI Express Linux driver
 * Copyright (c) 2015 - 2017 Beijing WangXun Technology Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 * based on ixgbe_param.c, Copyright(c) 1999 - 2017 Intel Corporation.
 * Contact Information:
 * Linux NICS <linux.nics@intel.com>
 * e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 */


#include <linux/types.h>
#include <linux/module.h>

#include "txgbe.h"

/* This is the only thing that needs to be changed to adjust the
 * maximum number of ports that the driver can manage.
 */
#define TXGBE_MAX_NIC   32
#define OPTION_UNSET    -1
#define OPTION_DISABLED 0
#define OPTION_ENABLED  1

#define STRINGIFY(foo)  #foo /* magic for getting defines into strings */
#define XSTRINGIFY(bar) STRINGIFY(bar)

#define TXGBE_PARAM_INIT { [0 ... TXGBE_MAX_NIC] = OPTION_UNSET }

#define TXGBE_PARAM(X, desc) \
	static int X[TXGBE_MAX_NIC+1] = TXGBE_PARAM_INIT; \
	static unsigned int num_##X; \
	module_param_array(X, int, &num_##X, 0); \
	MODULE_PARM_DESC(X, desc);

/* ffe_main (KR/KX4/KX/SFI)
 *
 * Valid Range: 0-60
 *
 * Default Value: 27
 */
TXGBE_PARAM(FFE_MAIN,
		 "TX_EQ MAIN (0 - 40)");
#define TXGBE_DEFAULT_FFE_MAIN              27

/* ffe_pre
 *
 * Valid Range: 0-60
 *
 * Default Value: 8
 */

TXGBE_PARAM(FFE_PRE,
		 "TX_EQ PRE (0 - 40)");
#define TXGBE_DEFAULT_FFE_PRE              8

/* ffe_post (VF Alloc Mode)
 *
 * Valid Range: 0-60
 *
 * Default Value: 44
 */

TXGBE_PARAM(FFE_POST,
		 "TX_EQ POST (0 - 40)");
#define TXGBE_DEFAULT_FFE_POST              44

/* ffe_set
 *
 * Valid Range: 0-4
 *
 * Default Value: 0
 */

TXGBE_PARAM(FFE_SET,
		 "TX_EQ SET must choose to take effect (0 = NULL, 1 = sfi, 2 = kr, 3 = kx4, 4 = kx)");
#define TXGBE_DEFAULT_FFE_SET              0

/* backplane_mode
 *
 * Valid Range: 0-4
 *  - 0 - NULL
 *  - 1 - sfi
 *  - 2 - kr
 *  - 3 - kx4
 *  - 4 - kx
 *
 * Default Value: 0
 */

TXGBE_PARAM(backplane_mode,
		 "Backplane Mode Support(0 = NULL, 1 = sfi, 2 = kr, 3 = kx4, 4 = kx)");

#define TXGBE_BP_NULL                      0
#define TXGBE_BP_SFI                       1
#define TXGBE_BP_KR                        2
#define TXGBE_BP_KX4                       3
#define TXGBE_BP_KX                        4
#define TXGBE_DEFAULT_BP_MODE              TXGBE_BP_NULL

/* backplane_auto
 *
 * Valid Range: 0-1
 *  - 0 - NO AUTO
 *  - 1 - AUTO
 * Default Value: 0
 */

TXGBE_PARAM(backplane_auto,
		 "Backplane AUTO mode (0 = NO AUTO, 1 = AUTO)");

#define TXGBE_BP_NAUTO                       0
#define TXGBE_BP_AUTO                        1
#define TXGBE_DEFAULT_BP_AUTO                -1

/* VF_alloc_mode (VF Alloc Mode)
 *
 * Valid Range: 0-1
 *  - 0 - 2 * 64
 *  - 1 - 4 * 32
 *  - 2 - 8 * 16
 *
 * Default Value: 2
 */

TXGBE_PARAM(vf_alloc_mode,
		 "Change VF Alloc Mode (0 = 2*64, 1 = 4*32, 2 = 8*16)");

#define TXGBE_2Q                	0
#define TXGBE_4Q                   	1
#define TXGBE_8Q                  	2
#define TXGBE_DEFAULT_NUMQ              TXGBE_2Q

/* IntMode (Interrupt Mode)
 *
 * Valid Range: 0-2
 *  - 0 - Legacy Interrupt
 *  - 1 - MSI Interrupt
 *  - 2 - MSI-X Interrupt(s)
 *
 * Default Value: 2
 */

TXGBE_PARAM(InterruptType,
		 "Change Interrupt Mode (0=Legacy, 1=MSI, 2=MSI-X), "
	    "default IntMode (deprecated)");

TXGBE_PARAM(IntMode,
			"Change Interrupt Mode (0=Legacy, 1=MSI, 2=MSI-X), "
			"default 2");

#define TXGBE_INT_LEGACY                0
#define TXGBE_INT_MSI                   1
#define TXGBE_INT_MSIX                  2
#define TXGBE_DEFAULT_INT               TXGBE_INT_MSIX

/* MQ - Multiple Queue enable/disable
 *
 * Valid Range: 0, 1
 *  - 0 - disables MQ
 *  - 1 - enables MQ
 *
 * Default Value: 1
 */

TXGBE_PARAM(MQ,
		 "Disable or enable Multiple Queues, default 1");

/* RSS - Receive-Side Scaling (RSS) Descriptor Queues
 *
 * Valid Range: 0-64
 *  - 0 - enables RSS and sets the Desc. Q's to min(64, num_online_cpus()).
 *  - 1-64 - enables RSS and sets the Desc. Q's to the specified value.
 *
 * Default Value: 0
 */

TXGBE_PARAM(RSS,
		 "Number of Receive-Side Scaling Descriptor Queues, "
	    "default 0=number of cpus");

/* VMDQ - Virtual Machine Device Queues (VMDQ)
 *
 * Valid Range: 1-16
 *  - 1 Disables VMDQ by allocating only a single queue.
 *  - 2-16 - enables VMDQ and sets the Desc. Q's to the specified value.
 *
 * Default Value: 1
 */

#define TXGBE_DEFAULT_NUM_VMDQ 8

TXGBE_PARAM(VMDQ,
		 "Number of Virtual Machine Device Queues: 0/1 = disable, "
	    "2-16 enable (default=" XSTRINGIFY(TXGBE_DEFAULT_NUM_VMDQ) ")");

/* Interrupt Throttle Rate (interrupts/sec)
 *
 * Valid Range: 980-500000 (0=off, 1=dynamic)
 *
 * Default Value: 1
 */
#define DEFAULT_ITR             1
TXGBE_PARAM(InterruptThrottleRate,
		 "Maximum interrupts per second, per vector, "
	    "(0,1,980-500000), default 1");

#define MAX_ITR         TXGBE_MAX_INT_RATE
#define MIN_ITR         TXGBE_MIN_INT_RATE

/* LLIPort (Low Latency Interrupt TCP Port)
 *
 * Valid Range: 0 - 65535
 *
 * Default Value: 0 (disabled)
 */
TXGBE_PARAM(LLIPort,
		 "Low Latency Interrupt TCP Port (0-65535)");

#define DEFAULT_LLIPORT         0
#define MAX_LLIPORT             0xFFFF
#define MIN_LLIPORT             0

/* LLISize (Low Latency Interrupt on Packet Size)
 *
 * Valid Range: 0 - 1500
 *
 * Default Value: 0 (disabled)
 */

TXGBE_PARAM(LLISize,
		 "Low Latency Interrupt on Packet Size (0-1500)");

#define DEFAULT_LLISIZE         0
#define MAX_LLISIZE             1500
#define MIN_LLISIZE             0

/* LLIEType (Low Latency Interrupt Ethernet Type)
 *
 * Valid Range: 0 - 0x8fff
 *
 * Default Value: 0 (disabled)
 */

TXGBE_PARAM(LLIEType,
		 "Low Latency Interrupt Ethernet Protocol Type");

#define DEFAULT_LLIETYPE        0
#define MAX_LLIETYPE            0x8fff
#define MIN_LLIETYPE            0

/* LLIVLANP (Low Latency Interrupt on VLAN priority threshold)
 *
 * Valid Range: 0 - 7
 *
 * Default Value: 0 (disabled)
 */

TXGBE_PARAM(LLIVLANP,
		 "Low Latency Interrupt on VLAN priority threshold");

#define DEFAULT_LLIVLANP        0
#define MAX_LLIVLANP            7
#define MIN_LLIVLANP            0

/* Flow Director packet buffer allocation level
 *
 * Valid Range: 1-3
 *   1 = 8k hash/2k perfect,
 *   2 = 16k hash/4k perfect,
 *   3 = 32k hash/8k perfect
 *
 * Default Value: 0
 */

TXGBE_PARAM(FdirPballoc,
		 "Flow Director packet buffer allocation level:\n"
	    "\t\t\t1 = 8k hash filters or 2k perfect filters\n"
	    "\t\t\t2 = 16k hash filters or 4k perfect filters\n"
	    "\t\t\t3 = 32k hash filters or 8k perfect filters");

#define TXGBE_DEFAULT_FDIR_PBALLOC TXGBE_FDIR_PBALLOC_64K

/* Software ATR packet sample rate
 *
 * Valid Range: 0-255  0 = off, 1-255 = rate of Tx packet inspection
 *
 * Default Value: 20
 */

TXGBE_PARAM(AtrSampleRate,
		 "Software ATR Tx packet sample rate");

#define TXGBE_MAX_ATR_SAMPLE_RATE       255
#define TXGBE_MIN_ATR_SAMPLE_RATE       1
#define TXGBE_ATR_SAMPLE_RATE_OFF       0
#define TXGBE_DEFAULT_ATR_SAMPLE_RATE   20

/* Enable/disable Large Receive Offload
 *
 * Valid Values: 0(off), 1(on)
 *
 * Default Value: 1
 */

TXGBE_PARAM(LRO,
		 "Large Receive Offload (0,1), default 1 = on");

/* Enable/disable support for untested SFP+ modules on adapters
 *
 * Valid Values: 0(Disable), 1(Enable)
 *
 * Default Value: 0
 */

TXGBE_PARAM(allow_unsupported_sfp,
		 "Allow unsupported and untested "
	    "SFP+ modules on adapters, default 0 = Disable");

/* Enable/disable support for DMA coalescing
 *
 * Valid Values: 0(off), 41 - 10000(on)
 *
 * Default Value: 0
 */

TXGBE_PARAM(dmac_watchdog,
		 "DMA coalescing watchdog in microseconds (0,41-10000),"
	    "default 0 = off");

/* Enable/disable support for VXLAN rx checksum offload
 *
 * Valid Values: 0(Disable), 1(Enable)
 *
 * Default Value: 1 on hardware that supports it
 */

TXGBE_PARAM(vxlan_rx,
		 "VXLAN receive checksum offload (0,1), default 1 = Enable");

/* Rx buffer mode
 *
 * Valid Range: 0-1 0 = no header split, 1 = hdr split
 *
 * Default Value: 0
 */

TXGBE_PARAM(RxBufferMode,
		 "0=(default)no header split\n"
			  "\t\t\t1=hdr split for recognized packet\n");

#define TXGBE_RXBUFMODE_NO_HEADER_SPLIT                 0
#define TXGBE_RXBUFMODE_HEADER_SPLIT                    1
#define TXGBE_DEFAULT_RXBUFMODE   TXGBE_RXBUFMODE_NO_HEADER_SPLIT

/* Cloud Switch mode
 *
 * Valid Range: 0-1 0 = disable Cloud Switch, 1 = enable Cloud Switch
 *
 * Default Value: 0
 */

TXGBE_PARAM(CloudSwitch,
		 "Cloud Switch (0,1), default 0 = disable, 1 = enable");

struct txgbe_option {
	enum { enable_option, range_option, list_option } type;
	const char *name;
	const char *err;
	const char *msg;
	int def;
	union {
		struct { /* range_option info */
			int min;
			int max;
		} r;
		struct { /* list_option info */
			int nr;
			const struct txgbe_opt_list {
				int i;
				char *str;
			} *p;
		} l;
	} arg;
};

static int txgbe_validate_option(u32 *value,
					   struct txgbe_option *opt)
{
	int val = (int)*value;

	if (val == OPTION_UNSET) {
		txgbe_info("txgbe: Invalid %s specified (%d),  %s\n",
			opt->name, val, opt->err);
		*value = (u32)opt->def;
		return 0;
	}

	switch (opt->type) {
	case enable_option:
		switch (val) {
		case OPTION_ENABLED:
			txgbe_info("txgbe: %s Enabled\n", opt->name);
			return 0;
		case OPTION_DISABLED:
			txgbe_info("txgbe: %s Disabled\n", opt->name);
			return 0;
		}
		break;
	case range_option:
		if ((val >= opt->arg.r.min && val <= opt->arg.r.max) ||
		    val == opt->def) {
			if (opt->msg)
				txgbe_info("txgbe: %s set to %d, %s\n",
				       opt->name, val, opt->msg);
			else
				txgbe_info("txgbe: %s set to %d\n",
				       opt->name, val);
			return 0;
		}
		break;
	case list_option: {
		int i;
		const struct txgbe_opt_list *ent;

		for (i = 0; i < opt->arg.l.nr; i++) {
			ent = &opt->arg.l.p[i];
			if (val == ent->i) {
				if (ent->str[0] != '\0')
					txgbe_info("%s\n", ent->str);
				return 0;
			}
		}
	}
		break;
	default:
		BUG_ON(1);
	}

	txgbe_info("txgbe: Invalid %s specified (%d),  %s\n",
	       opt->name, val, opt->err);
	*value = (u32)opt->def;
	return -1;
}

/**
 * txgbe_check_options - Range Checking for Command Line Parameters
 * @adapter: board private structure
 *
 * This routine checks all command line parameters for valid user
 * input.  If an invalid value is given, or if no user specified
 * value exists, a default value is used.  The final value is stored
 * in a variable in the adapter structure.
 **/
void txgbe_check_options(struct txgbe_adapter *adapter)
{
	u32 bd = adapter->bd_number;
	u32 *aflags = &adapter->flags;
	struct txgbe_ring_feature *feature = adapter->ring_feature;
	u32 vmdq;

	if (bd >= TXGBE_MAX_NIC) {
		txgbe_notice(
		       "Warning: no configuration for board #%d\n", bd);
		txgbe_notice("Using defaults for all values\n");
	}
		{ /* MAIN */
			u32 ffe_main;
			static struct txgbe_option opt = {
				.type = range_option,
				.name = "FFE_MAIN",
				.err =
				  "using default of "__MODULE_STRING(TXGBE_DEFAULT_FFE_MAIN),
				.def = TXGBE_DEFAULT_FFE_MAIN,
				.arg = { .r = { .min = 0,
						.max = 60} }
			};

			if (num_FFE_MAIN > bd) {
				ffe_main = FFE_MAIN[bd];
				if (ffe_main == OPTION_UNSET)
					ffe_main = FFE_MAIN[bd];
				txgbe_validate_option(&ffe_main, &opt);
				adapter->ffe_main = ffe_main;
			} else {
				adapter->ffe_main = 27;
			}
		}

		{ /* PRE */
			u32 ffe_pre;
			static struct txgbe_option opt = {
				.type = range_option,
				.name = "FFE_PRE",
				.err =
				  "using default of "__MODULE_STRING(TXGBE_DEFAULT_FFE_PRE),
				.def = TXGBE_DEFAULT_FFE_PRE,
				.arg = { .r = { .min = 0,
						.max = 60} }
			};

			if (num_FFE_PRE > bd) {
				ffe_pre = FFE_PRE[bd];
				if (ffe_pre == OPTION_UNSET)
					ffe_pre = FFE_PRE[bd];
				txgbe_validate_option(&ffe_pre, &opt);
				adapter->ffe_pre = ffe_pre;
			} else {
				adapter->ffe_pre = 8;
			}
		}

		{ /* POST */
			u32 ffe_post;
			static struct txgbe_option opt = {
				.type = range_option,
				.name = "FFE_POST",
				.err =
				  "using default of "__MODULE_STRING(TXGBE_DEFAULT_FFE_POST),
				.def = TXGBE_DEFAULT_FFE_POST,
				.arg = { .r = { .min = 0,
						.max = 60} }
			};

			if (num_FFE_POST > bd) {
				ffe_post = FFE_POST[bd];
				if (ffe_post == OPTION_UNSET)
					ffe_post = FFE_POST[bd];
				txgbe_validate_option(&ffe_post, &opt);
				adapter->ffe_post = ffe_post;
			} else {
						adapter->ffe_post = 44;
			}
		}

			{ /* ffe_set */
			u32 ffe_set;
			static struct txgbe_option opt = {
				.type = range_option,
				.name = "FFE_SET",
				.err =
				  "using default of "__MODULE_STRING(TXGBE_DEFAULT_FFE_SET),
				.def = TXGBE_DEFAULT_FFE_SET,
				.arg = { .r = { .min = 0,
						.max = 4} }
			};

			if (num_FFE_SET > bd) {
				ffe_set = FFE_SET[bd];
				if (ffe_set == OPTION_UNSET)
					ffe_set = FFE_SET[bd];
				txgbe_validate_option(&ffe_set, &opt);
				adapter->ffe_set = ffe_set;
			} else {
						adapter->ffe_set = 0;
			}
		}

		{ /* backplane_mode */
			u32 bp_mode;
			static struct txgbe_option opt = {
				.type = range_option,
				.name = "backplane_mode",
				.err =
				  "using default of "__MODULE_STRING(TXGBE_DEFAULT_BP_MODE),
				.def = TXGBE_DEFAULT_BP_MODE,
				.arg = { .r = { .min = 0,
						.max = 4} }
			};

			if (num_backplane_mode > bd) {
				bp_mode = backplane_mode[bd];
				if (bp_mode == OPTION_UNSET)
					bp_mode = backplane_mode[bd];
				txgbe_validate_option(&bp_mode, &opt);
				adapter->backplane_mode = bp_mode;
			} else {
						adapter->backplane_mode = 0;
			}
		}

		{ /* auto mode */
			u32 bp_auto;
			static struct txgbe_option opt = {
				.type = range_option,
				.name = "bp_auto",
				.err =
				  "using default of "__MODULE_STRING(TXGBE_DEFAULT_BP_AUTO),
				.def = TXGBE_DEFAULT_BP_AUTO,
				.arg = { .r = { .min = 0,
						.max = 2} }
			};

			if (num_backplane_auto > bd) {
				bp_auto = backplane_auto[bd];
				if (bp_auto == OPTION_UNSET)
					bp_auto = backplane_auto[bd];
				txgbe_validate_option(&bp_auto, &opt);
				adapter->backplane_auto = bp_auto;
			} else {
						adapter->backplane_auto = -1;
			}
		}

	{ /* VF_alloc_mode */
		u32 vf_mode;
		static struct txgbe_option opt = {
			.type = range_option,
			.name = "vf_alloc_mode",
			.err =
			  "using default of "__MODULE_STRING(TXGBE_DEFAULT_NUMQ),
			.def = TXGBE_DEFAULT_NUMQ,
			.arg = { .r = { .min = TXGBE_2Q,
					.max = TXGBE_8Q} }
		};

		if (num_vf_alloc_mode > bd) {
			vf_mode = vf_alloc_mode[bd];
			if (vf_mode == OPTION_UNSET)
				vf_mode = vf_alloc_mode[bd];
			txgbe_validate_option(&vf_mode, &opt);
			switch (vf_mode) {
			case TXGBE_8Q:
					adapter->vf_mode = 15;
				break;
			case TXGBE_4Q:
					adapter->vf_mode = 31;
				break;
			case TXGBE_2Q:
			default:
					adapter->vf_mode = 63;
				break;
			}
		} else {
					adapter->vf_mode = 63;
		}
	}
	{ /* Interrupt Mode */
		u32 int_mode;
		static struct txgbe_option opt = {
			.type = range_option,
			.name = "Interrupt Mode",
			.err =
			  "using default of "__MODULE_STRING(TXGBE_DEFAULT_INT),
			.def = TXGBE_DEFAULT_INT,
			.arg = { .r = { .min = TXGBE_INT_LEGACY,
					.max = TXGBE_INT_MSIX} }
		};

		if (num_IntMode > bd || num_InterruptType > bd) {
			int_mode = IntMode[bd];
			if (int_mode == OPTION_UNSET)
				int_mode = InterruptType[bd];
			txgbe_validate_option(&int_mode, &opt);
			switch (int_mode) {
			case TXGBE_INT_MSIX:
				if (!(*aflags & TXGBE_FLAG_MSIX_CAPABLE))
					txgbe_info(
					       "Ignoring MSI-X setting; "
					       "support unavailable\n");
				break;
			case TXGBE_INT_MSI:
				if (!(*aflags & TXGBE_FLAG_MSI_CAPABLE)) {
					txgbe_info(
					       "Ignoring MSI setting; "
					       "support unavailable\n");
				} else {
					*aflags &= ~TXGBE_FLAG_MSIX_CAPABLE;
				}
				break;
			case TXGBE_INT_LEGACY:
			default:
				*aflags &= ~TXGBE_FLAG_MSIX_CAPABLE;
				*aflags &= ~TXGBE_FLAG_MSI_CAPABLE;
				break;
			}
		} else {
			/* default settings */
			if (opt.def == TXGBE_INT_MSIX &&
			    *aflags & TXGBE_FLAG_MSIX_CAPABLE) {
				*aflags |= TXGBE_FLAG_MSIX_CAPABLE;
				*aflags |= TXGBE_FLAG_MSI_CAPABLE;
			} else if (opt.def == TXGBE_INT_MSI &&
			    *aflags & TXGBE_FLAG_MSI_CAPABLE) {
				*aflags &= ~TXGBE_FLAG_MSIX_CAPABLE;
				*aflags |= TXGBE_FLAG_MSI_CAPABLE;
			} else {
				*aflags &= ~TXGBE_FLAG_MSIX_CAPABLE;
				*aflags &= ~TXGBE_FLAG_MSI_CAPABLE;
			}
		}
	}
	{ /* Multiple Queue Support */
		static struct txgbe_option opt = {
			.type = enable_option,
			.name = "Multiple Queue Support",
			.err  = "defaulting to Enabled",
			.def  = OPTION_ENABLED
		};

		if (num_MQ > bd) {
			u32 mq = MQ[bd];
			txgbe_validate_option(&mq, &opt);
			if (mq)
				*aflags |= TXGBE_FLAG_MQ_CAPABLE;
			else
				*aflags &= ~TXGBE_FLAG_MQ_CAPABLE;
		} else {
			if (opt.def == OPTION_ENABLED)
				*aflags |= TXGBE_FLAG_MQ_CAPABLE;
			else
				*aflags &= ~TXGBE_FLAG_MQ_CAPABLE;
		}
		/* Check Interoperability */
		if ((*aflags & TXGBE_FLAG_MQ_CAPABLE) &&
				!(*aflags & TXGBE_FLAG_MSIX_CAPABLE)) {
			DPRINTK(PROBE, INFO,
				"Multiple queues are not supported while MSI-X "
				"is disabled.  Disabling Multiple Queues.\n");
			*aflags &= ~TXGBE_FLAG_MQ_CAPABLE;
		}
	}

	{ /* Receive-Side Scaling (RSS) */
		static struct txgbe_option opt = {
			.type = range_option,
			.name = "Receive-Side Scaling (RSS)",
			.err  = "using default.",
			.def  = 0,
			.arg  = { .r = { .min = 0,
					 .max = 1} }
		};
		u32 rss = RSS[bd];
		/* adjust Max allowed RSS queues based on MAC type */
		opt.arg.r.max = txgbe_max_rss_indices(adapter);

		if (num_RSS > bd) {
			txgbe_validate_option(&rss, &opt);
			/* base it off num_online_cpus() with hardware limit */
			if (!rss)
				rss = min_t(int, opt.arg.r.max,
					    num_online_cpus());
			else
				feature[RING_F_FDIR].limit = (u16)rss;

			feature[RING_F_RSS].limit = (u16)rss;
		} else if (opt.def == 0) {
			rss = min_t(int, txgbe_max_rss_indices(adapter),
				    num_online_cpus());
			feature[RING_F_RSS].limit = rss;
		}
		/* Check Interoperability */
		if (rss > 1) {
			if (!(*aflags & TXGBE_FLAG_MQ_CAPABLE)) {
				DPRINTK(PROBE, INFO,
					"Multiqueue is disabled.  "
					"Limiting RSS.\n");
				feature[RING_F_RSS].limit = 1;
			}
		}
		adapter->flags2 |= TXGBE_FLAG2_RSS_ENABLED;
	}
	{ /* Virtual Machine Device Queues (VMDQ) */
		static struct txgbe_option opt = {
			.type = range_option,
			.name = "Virtual Machine Device Queues (VMDQ)",
			.err  = "defaulting to Disabled",
			.def  = OPTION_DISABLED,
			.arg  = { .r = { .min = OPTION_DISABLED,
					 .max = TXGBE_MAX_VMDQ_INDICES
				} }
		};

		if (num_VMDQ > bd) {
			vmdq = VMDQ[bd];

			txgbe_validate_option(&vmdq, &opt);

			/* zero or one both mean disabled from our driver's
			 * perspective */
			if (vmdq > 1) {
				*aflags |= TXGBE_FLAG_VMDQ_ENABLED;
			} else
				*aflags &= ~TXGBE_FLAG_VMDQ_ENABLED;

			feature[RING_F_VMDQ].limit = (u16)vmdq;
		} else {
			if (opt.def == OPTION_DISABLED)
				*aflags &= ~TXGBE_FLAG_VMDQ_ENABLED;
			else
				*aflags |= TXGBE_FLAG_VMDQ_ENABLED;

			feature[RING_F_VMDQ].limit = opt.def;
		}
		/* Check Interoperability */
		if (*aflags & TXGBE_FLAG_VMDQ_ENABLED) {
			if (!(*aflags & TXGBE_FLAG_MQ_CAPABLE)) {
				DPRINTK(PROBE, INFO,
					"VMDQ is not supported while multiple "
					"queues are disabled.  "
					"Disabling VMDQ.\n");
				*aflags &= ~TXGBE_FLAG_VMDQ_ENABLED;
				feature[RING_F_VMDQ].limit = 0;
			}
		}
	}

	{ /* Interrupt Throttling Rate */
		static struct txgbe_option opt = {
			.type = range_option,
			.name = "Interrupt Throttling Rate (ints/sec)",
			.err  = "using default of "__MODULE_STRING(DEFAULT_ITR),
			.def  = DEFAULT_ITR,
			.arg  = { .r = { .min = MIN_ITR,
					 .max = MAX_ITR } }
		};

		if (num_InterruptThrottleRate > bd) {
			u32 itr = InterruptThrottleRate[bd];
			switch (itr) {
			case 0:
				DPRINTK(PROBE, INFO, "%s turned off\n",
					opt.name);
				adapter->rx_itr_setting = 0;
				break;
			case 1:
				DPRINTK(PROBE, INFO, "dynamic interrupt "
					"throttling enabled\n");
				adapter->rx_itr_setting = 1;
				break;
			default:
				txgbe_validate_option(&itr, &opt);
				/* the first bit is used as control */
				adapter->rx_itr_setting = (u16)((1000000/itr) << 2);
				break;
			}
			adapter->tx_itr_setting = adapter->rx_itr_setting;
		} else {
			adapter->rx_itr_setting = opt.def;
			adapter->tx_itr_setting = opt.def;
		}
	}

	{ /* Low Latency Interrupt TCP Port*/
		static struct txgbe_option opt = {
			.type = range_option,
			.name = "Low Latency Interrupt TCP Port",
			.err  = "using default of "
					__MODULE_STRING(DEFAULT_LLIPORT),
			.def  = DEFAULT_LLIPORT,
			.arg  = { .r = { .min = MIN_LLIPORT,
					 .max = MAX_LLIPORT } }
		};

		if (num_LLIPort > bd) {
			adapter->lli_port = LLIPort[bd];
			if (adapter->lli_port) {
				txgbe_validate_option(&adapter->lli_port, &opt);
			} else {
				DPRINTK(PROBE, INFO, "%s turned off\n",
					opt.name);
			}
		} else {
			adapter->lli_port = opt.def;
		}
	}
	{ /* Low Latency Interrupt on Packet Size */
		static struct txgbe_option opt = {
			.type = range_option,
			.name = "Low Latency Interrupt on Packet Size",
			.err  = "using default of "
					__MODULE_STRING(DEFAULT_LLISIZE),
			.def  = DEFAULT_LLISIZE,
			.arg  = { .r = { .min = MIN_LLISIZE,
					 .max = MAX_LLISIZE } }
		};

		if (num_LLISize > bd) {
			adapter->lli_size = LLISize[bd];
			if (adapter->lli_size) {
				txgbe_validate_option(&adapter->lli_size, &opt);
			} else {
				DPRINTK(PROBE, INFO, "%s turned off\n",
					opt.name);
			}
		} else {
			adapter->lli_size = opt.def;
		}
	}
	{ /* Low Latency Interrupt EtherType*/
		static struct txgbe_option opt = {
			.type = range_option,
			.name = "Low Latency Interrupt on Ethernet Protocol "
				"Type",
			.err  = "using default of "
					__MODULE_STRING(DEFAULT_LLIETYPE),
			.def  = DEFAULT_LLIETYPE,
			.arg  = { .r = { .min = MIN_LLIETYPE,
					 .max = MAX_LLIETYPE } }
		};

		if (num_LLIEType > bd) {
			adapter->lli_etype = LLIEType[bd];
			if (adapter->lli_etype) {
				txgbe_validate_option(&adapter->lli_etype,
						      &opt);
			} else {
				DPRINTK(PROBE, INFO, "%s turned off\n",
					opt.name);
			}
		} else {
			adapter->lli_etype = opt.def;
		}
	}
	{ /* LLI VLAN Priority */
		static struct txgbe_option opt = {
			.type = range_option,
			.name = "Low Latency Interrupt on VLAN priority "
				"threshold",
			.err  = "using default of "
					__MODULE_STRING(DEFAULT_LLIVLANP),
			.def  = DEFAULT_LLIVLANP,
			.arg  = { .r = { .min = MIN_LLIVLANP,
					 .max = MAX_LLIVLANP } }
		};

		if (num_LLIVLANP > bd) {
			adapter->lli_vlan_pri = LLIVLANP[bd];
			if (adapter->lli_vlan_pri) {
				txgbe_validate_option(&adapter->lli_vlan_pri,
						      &opt);
			} else {
				DPRINTK(PROBE, INFO, "%s turned off\n",
					opt.name);
			}
		} else {
			adapter->lli_vlan_pri = opt.def;
		}
	}

	{ /* Flow Director packet buffer allocation */
		u32 fdir_pballoc_mode;
		static struct txgbe_option opt = {
			.type = range_option,
			.name = "Flow Director packet buffer allocation",
			.err = "using default of "
				__MODULE_STRING(TXGBE_DEFAULT_FDIR_PBALLOC),
			.def = TXGBE_DEFAULT_FDIR_PBALLOC,
			.arg = {.r = {.min = TXGBE_FDIR_PBALLOC_64K,
				      .max = TXGBE_FDIR_PBALLOC_256K} }
		};
		const char *pstring;

		if (num_FdirPballoc > bd) {
			fdir_pballoc_mode = FdirPballoc[bd];
			txgbe_validate_option(&fdir_pballoc_mode, &opt);
			switch (fdir_pballoc_mode) {
			case TXGBE_FDIR_PBALLOC_256K:
				adapter->fdir_pballoc = TXGBE_FDIR_PBALLOC_256K;
				pstring = "256kB";
				break;
			case TXGBE_FDIR_PBALLOC_128K:
				adapter->fdir_pballoc = TXGBE_FDIR_PBALLOC_128K;
				pstring = "128kB";
				break;
			case TXGBE_FDIR_PBALLOC_64K:
			default:
				adapter->fdir_pballoc = TXGBE_FDIR_PBALLOC_64K;
				pstring = "64kB";
				break;
			}
			DPRINTK(PROBE, INFO, "Flow Director will be allocated "
				"%s of packet buffer\n", pstring);
		} else {
			adapter->fdir_pballoc = opt.def;
		}

	}
	{ /* Flow Director ATR Tx sample packet rate */
		static struct txgbe_option opt = {
			.type = range_option,
			.name = "Software ATR Tx packet sample rate",
			.err = "using default of "
				__MODULE_STRING(TXGBE_DEFAULT_ATR_SAMPLE_RATE),
			.def = TXGBE_DEFAULT_ATR_SAMPLE_RATE,
			.arg = {.r = {.min = TXGBE_ATR_SAMPLE_RATE_OFF,
				      .max = TXGBE_MAX_ATR_SAMPLE_RATE} }
		};
		static const char atr_string[] =
					    "ATR Tx Packet sample rate set to";

		if (num_AtrSampleRate > bd) {
			adapter->atr_sample_rate = AtrSampleRate[bd];

			if (adapter->atr_sample_rate) {
				txgbe_validate_option(&adapter->atr_sample_rate,
						      &opt);
				DPRINTK(PROBE, INFO, "%s %d\n", atr_string,
					adapter->atr_sample_rate);
			}
		} else {
			adapter->atr_sample_rate = opt.def;
		}
	}

	{ /* LRO - Set Large Receive Offload */
		struct txgbe_option opt = {
			.type = enable_option,
			.name = "LRO - Large Receive Offload",
			.err  = "defaulting to Disabled",
			.def  = OPTION_ENABLED
		};
		struct net_device *netdev = adapter->netdev;

		if (!(adapter->flags2 & TXGBE_FLAG2_RSC_CAPABLE))
			opt.def = OPTION_DISABLED;
		if (num_LRO > bd) {
			u32 lro = LRO[bd];
			txgbe_validate_option(&lro, &opt);
			if (lro)
				netdev->features |= NETIF_F_LRO;
			else
				netdev->features &= ~NETIF_F_LRO;
		} else if (opt.def == OPTION_ENABLED) {
			netdev->features |= NETIF_F_LRO;
		} else {
			netdev->features &= ~NETIF_F_LRO;
		}

		if ((netdev->features & NETIF_F_LRO) &&
		    !(adapter->flags2 & TXGBE_FLAG2_RSC_CAPABLE)) {
			DPRINTK(PROBE, INFO,
				"RSC is not supported on this "
				"hardware.  Disabling RSC.\n");
			netdev->features &= ~NETIF_F_LRO;
		}
	}
	{ /*
	   * allow_unsupported_sfp - Enable/Disable support for unsupported
	   * and untested SFP+ modules.
	   */
	struct txgbe_option opt = {
			.type = enable_option,
			.name = "allow_unsupported_sfp",
			.err  = "defaulting to Disabled",
			.def  = OPTION_DISABLED
		};
		if (num_allow_unsupported_sfp > bd) {
			u32 enable_unsupported_sfp =
						      allow_unsupported_sfp[bd];
			txgbe_validate_option(&enable_unsupported_sfp, &opt);
			if (enable_unsupported_sfp) {
				adapter->hw.allow_unsupported_sfp = true;
			} else {
				adapter->hw.allow_unsupported_sfp = false;
			}
		} else if (opt.def == OPTION_ENABLED) {
				adapter->hw.allow_unsupported_sfp = true;
		} else {
				adapter->hw.allow_unsupported_sfp = false;
		}
	}

	{ /* DMA Coalescing */
		struct txgbe_option opt = {
			.type = range_option,
			.name = "dmac_watchdog",
			.err  = "defaulting to 0 (disabled)",
			.def  = 0,
			.arg  = { .r = { .min = 41, .max = 10000 } },
		};
		const char *cmsg = "DMA coalescing not supported on this "
				   "hardware";

		opt.err = cmsg;
		opt.msg = cmsg;
		opt.arg.r.min = 0;
		opt.arg.r.max = 0;

		if (num_dmac_watchdog > bd) {
			u32 dmac_wd = dmac_watchdog[bd];

			txgbe_validate_option(&dmac_wd, &opt);
			adapter->hw.mac.dmac_config.watchdog_timer = (u16)dmac_wd;
		} else {
			adapter->hw.mac.dmac_config.watchdog_timer = opt.def;
		}
	}
	{ /* VXLAN rx offload */
		struct txgbe_option opt = {
			.type = range_option,
			.name = "vxlan_rx",
			.err  = "defaulting to 1 (enabled)",
			.def  = 1,
			.arg  = { .r = { .min = 0, .max = 1 } },
		};
		const char *cmsg = "VXLAN rx offload not supported on this "
				   "hardware";
		const u32 flag = TXGBE_FLAG_VXLAN_OFFLOAD_ENABLE;

		if (!(adapter->flags & TXGBE_FLAG_VXLAN_OFFLOAD_CAPABLE)) {
			opt.err = cmsg;
			opt.msg = cmsg;
			opt.def = 0;
			opt.arg.r.max = 0;
		}
		if (num_vxlan_rx > bd) {
			u32 enable_vxlan_rx = vxlan_rx[bd];

			txgbe_validate_option(&enable_vxlan_rx, &opt);
			if (enable_vxlan_rx)
				adapter->flags |= flag;
			else
				adapter->flags &= ~flag;
		} else if (opt.def) {
			adapter->flags |= flag;
		} else {
			adapter->flags &= ~flag;
		}
	}

	{ /* Rx buffer mode */
		u32 rx_buf_mode;
		static struct txgbe_option opt = {
			.type = range_option,
			.name = "Rx buffer mode",
			.err = "using default of "
				__MODULE_STRING(TXGBE_DEFAULT_RXBUFMODE),
			.def = TXGBE_DEFAULT_RXBUFMODE,
			.arg = {.r = {.min = TXGBE_RXBUFMODE_NO_HEADER_SPLIT,
							.max = TXGBE_RXBUFMODE_HEADER_SPLIT} }

		};

		if (num_RxBufferMode > bd) {
			rx_buf_mode = RxBufferMode[bd];
			txgbe_validate_option(&rx_buf_mode, &opt);
			switch (rx_buf_mode) {
			case TXGBE_RXBUFMODE_NO_HEADER_SPLIT:
				*aflags &= ~TXGBE_FLAG_RX_HS_ENABLED;
				break;
			case TXGBE_RXBUFMODE_HEADER_SPLIT:
				*aflags |= TXGBE_FLAG_RX_HS_ENABLED;
				break;
			default:
				break;
			}
		} else {
			*aflags &= ~TXGBE_FLAG_RX_HS_ENABLED;
		}

	}
	{ /* Cloud Switch */
		struct txgbe_option opt = {
			.type = range_option,
			.name = "CloudSwitch",
			.err  = "defaulting to 0 (disabled)",
			.def  = 0,
			.arg  = { .r = { .min = 0, .max = 1 } },
		};

		if (num_CloudSwitch > bd) {
			u32 enable_cloudswitch = CloudSwitch[bd];

			txgbe_validate_option(&enable_cloudswitch, &opt);
			if (enable_cloudswitch)
				adapter->flags |=
					TXGBE_FLAG2_CLOUD_SWITCH_ENABLED;
			else
				adapter->flags &=
					~TXGBE_FLAG2_CLOUD_SWITCH_ENABLED;
		} else if (opt.def) {
			adapter->flags |= TXGBE_FLAG2_CLOUD_SWITCH_ENABLED;
		} else {
			adapter->flags &= ~TXGBE_FLAG2_CLOUD_SWITCH_ENABLED;
		}
	}
}
