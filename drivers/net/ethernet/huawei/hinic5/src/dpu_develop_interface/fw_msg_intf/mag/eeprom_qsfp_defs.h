/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : eeprom_qsfp_defs.h
 * Version       : Initial Draft
 * Created       : 2024-04-15
 * Last Modified : 2026/09/16
 * Description   : sfp data definition
 */

#ifndef EEPROM_QSFP_DEFS_H
#define EEPROM_QSFP_DEFS_H

typedef struct {
    /* offset 0 */
	u8 ucId; /* identifier (1 Byte), the definition of identifier field is the same as page 00h byte 128 */

    /* offset 1~2 */
	struct {
	u8 ucRsvd1;

	u8 ucDataNotReady : 1; /* indicate transceiver has not yet achieved power up and monitor data is
				* not ready.  Bit remains high until data is ready to be read at which time
				* the device sets the bit low. 2 bit 0
				*/
	u8 ucIntL         : 1; /* digital state of the IntL interrupt output pin. 2 bit 1 */
	u8 ucRsvd2        : 6; /* reserved. 2[7:2] */
	} stStatus;

    /* offset 3~21 */
	struct {
	/* channel status interrupt flags, offset 3~5 */
	u8 ucRxTxLos;
	u8 ucTxFault;
	u8 ucReserved2; /* reserved, 5 */

	/* module monitor interrupt flags, offset 6~8 */
	struct {
		u8 ucReserved1        : 4; /* reserved, 6[3:0] */
		u8 ucLTempWarningLow  : 1; /* latched low temperature warning, 6 bit 4 */
		u8 ucLTempWarningHigh : 1; /* latched high temperature warning, 6 bit 5 */
		u8 ucLTempAlarmLow    : 1; /* latched low temperature alarm, 6 bit 6 */
		u8 ucLTempAlarmHigh   : 1; /* latched high temperature alarm, 6 bit 7 */

		u8 ucReserved2        : 4; /* reserved, 7[3:0] */
		u8 ucLVccWarningLow   : 1; /* latched low supply voltage warning, 7 bit 4 */
		u8 ucLVccWarningHigh  : 1; /* latched high supply voltage warning, 7 bit 5 */
		u8 ucLVccAlarmLow     : 1; /* latched low supply voltage alarm, 7 bit 6 */
		u8 ucLVccAlarmHigh    : 1; /* latched high supply voltage alarm, 7 bit 7 */

		u8 ucReserved3;            /* reserved, 8 */
	} stModMtIntFlags;

	/* channel monitor interrupt flags, offset 9~21 */
	struct {
		/* channel power monitor interrupt flags */
		/* channel 2 Rx power monitor interrupt flags */
		u8 ucLRx2PowerWarningLow  : 1; /* latched low RX power warning, channel 2, 9 bit 0 */
		u8 ucLRx2PowerWarningHigh : 1; /* latched high RX power warning, channel 2, 9 bit 1 */
		u8 ucLRx2PowerAlarmLow    : 1; /* latched low RX power alarm, channel 2, 9 bit 2 */
		u8 ucLRx2PowerAlarmHigh   : 1; /* latched high RX power alarm, channel 2, 9 bit 3 */

		/* channel 1 Rx power monitor interrupt flags */
		u8 ucLRx1PowerWarningLow  : 1; /* latched low RX power warning, channel 1, 9 bit 4 */
		u8 ucLRx1PowerWarningHigh : 1; /* latched high RX power warning, channel 1, 9 bit 5 */
		u8 ucLRx1PowerAlarmLow    : 1; /* latched low RX power alarm, channel 1, 9 bit 6 */
		u8 ucLRx1PowerAlarmHigh   : 1; /* latched high RX power alarm, channel 1, 9 bit 7 */

		/* channel 4 Rx power monitor interrupt flags */
		u8 ucLRx4PowerWarningLow  : 1; /* latched low RX power warning, channel 4, 10 bit 0 */
		u8 ucLRx4PowerWarningHigh : 1; /* latched high RX power warning, channel 4, 10 bit 1 */
		u8 ucLRx4PowerAlarmLow    : 1; /* latched low RX power alarm, channel 4, 10 bit 2 */
		u8 ucLRx4PowerAlarmHigh   : 1; /* latched high RX power alarm, channel 4, 10 bit 3 */

		/* channel 3 Rx power monitor interrupt flags */
		u8 ucLRx3PowerWarningLow  : 1; /* latched low RX power warning, channel 3, 10 bit 4 */
		u8 ucLRx3PowerWarningHigh : 1; /* latched high RX power warning, channel 3, 10 bit 5 */
		u8 ucLRx3PowerAlarmLow    : 1; /* latched low RX power alarm, channel 3, 10 bit 6 */
		u8 ucLRx3PowerAlarmHigh   : 1; /* latched high RX power alarm, channel 3, 10 bit 7 */

		/* channel bias monitor interrupt flags */
		/* channel 2 Tx bias monitor interrupt flags */
		u8 ucLTx2BiasWarningLow   : 1; /* latched low TX bias warning, channel 2, 11 bit 0 */
		u8 ucLTx2BiasWarningHigh  : 1; /* latched high TX bias warning, channel 2, 11 bit 1 */
		u8 ucLTx2BiasAlarmLow     : 1; /* latched low TX bias alarm, channel 2, 11 bit 2 */
		u8 ucLTx2BiasAlarmHigh    : 1; /* latched high TX bias alarm, channel 2, 11 bit 3 */

		/* channel 1 Tx bias monitor interrupt flags */
		u8 ucLTx1BiasWarningLow   : 1; /* latched low TX bias warning, channel 1, 11 bit 4 */
		u8 ucLTx1BiasWarningHigh  : 1; /* latched high TX bias warning, channel 1, 11 bit 5 */
		u8 ucLTx1BiasAlarmLow     : 1; /* latched low TX bias alarm, channel 1, 11 bit 6 */
		u8 ucLTx1BiasAlarmHigh    : 1; /* latched high TX bias alarm, channel 1, 11 bit 7 */

		/* channel 4 Tx bias monitor interrupt flags */
		u8 ucLTx4BiasWarningLow   : 1; /* latched low TX bias warning, channel 4, 12 bit 0 */
		u8 ucLTx4BiasWarningHigh  : 1; /* latched high TX bias warning, channel 4, 12 bit 1 */
		u8 ucLTx4BiasAlarmLow     : 1; /* latched low TX bias alarm, channel 4, 12 bit 2 */
		u8 ucLTx4BiasAlarmHigh    : 1; /* latched high TX bias alarm, channel 4, 12 bit 3 */

		/* channel 3 Tx bias monitor interrupt flags */
		u8 ucLTx3BiasWarningLow   : 1; /* latched low TX bias warning, channel 3, 12 bit 4 */
		u8 ucLTx3BiasWarningHigh  : 1; /* latched high TX bias warning, channel 3, 12 bit 5 */
		u8 ucLTx3BiasAlarmLow     : 1; /* latched low TX bias alarm, channel 3, 12 bit 6 */
		u8 ucLTx3BiasAlarmHigh    : 1; /* latched high TX bias alarm, channel 3, 12 bit 7 */

		u8 ucReserved1[2];             /* reserved channel monitor flags, set 3 */
		u8 ucReserved2[2];             /* reserved channel monitor flags, set 4 */
		u8 ucReserved3[2];             /* reserved channel monitor flags, set 5 */
		u8 ucReserved4[2];             /* reserved channel monitor flags, set 6 */

		u8 ucReserved5;                /* reserved */
	} stChMtIntFlags;
	} stIntFlags;

    /* module monitoring values, offset 22~33 */
	struct {
	u8 ucTemperatureMSB; /* internally measured module temperature */
	u8 ucTemperatureLSB; /* internally measured module temperature */
	u8 ucReserved1[2];
	u8 ucSupplyVol[2];
	u8 ucReserved2[6];
	} stModMtValues;

    /* channel monitoring values, offset 34~81 */
	struct {
	u8 ucRxPow[8];
	u8 ucTxBias[8];
	u8 ucTxPow[8];
	u8 ucReserved2[8]; /* reserved channel monitor set 4, 58~65 */
	u8 ucReserved3[8]; /* reserved channel monitor set 5, 66~73 */
	u8 ucReserved4[8]; /* reserved channel monitor set 6, 74~81 */
	} stChMtValues;

    /* reserved (4 Bytes), offset 82~85 */
	u8 ucReserved1[4];

    /* control bytes, offset 86~99 */
	struct {
	u8 ucTxDisable;
	u8 ucRxRateSelect;
	u8 ucTxRateSelect;

	u8 ucRx4ApplicationSelect; /* software application select per SFF-8079, Rx channel 4 (optional) */
	u8 ucRx3ApplicationSelect; /* software application select per SFF-8079, Rx channel 3 (optional) */
	u8 ucRx2ApplicationSelect; /* software application select per SFF-8079, Rx channel 2 (optional) */
	u8 ucRx1ApplicationSelect; /* software application select per SFF-8079, Rx channel 1 (optional) */

	u8 ucPowerOverRide : 1;    /* override of LPMode signal setting the power mode with software. 93 bit 0 */
	u8 ucPowerSet      : 1;    /* power set to low power mode. Default 0. 93 bit 1 */
	u8 ucReserverd2    : 6;    /* reserved, 93[7:2] */

	u8 ucTx4ApplicationSelect; /* software application select per SFF-8079, Tx channel 4 (optional), 94 */
	u8 ucTx3ApplicationSelect; /* software application select per SFF-8079, Tx channel 3 (optional), 95 */
	u8 ucTx2ApplicationSelect; /* software application select per SFF-8079, Tx channel 2 (optional), 96 */
	u8 ucTx1ApplicationSelect; /* software application select per SFF-8079, Tx channel 1 (optional), 97 */

	u8 ucReserverd3[2];        /* reserved, 98~99 */
	} stCtrlBytes;

    /* module and channel masks, 100~106 */
	struct {
	u8 ucMRx1LOS          : 1; /* masking bit for RX LOS indicator, channel 1, 100 bit 0 */
	u8 ucMRx2LOS          : 1; /* masking bit for RX LOS indicator, channel 2, 100 bit 1 */
	u8 ucMRx3LOS          : 1; /* masking bit for RX LOS indicator, channel 3, 100 bit 2 */
	u8 ucMRx4LOS          : 1; /* masking bit for RX LOS indicator, channel 4, 100 bit 3 */

	u8 ucMTx1LOS          : 1; /* masking bit for TX LOS indicator, channel 1 (optional), 100 bit 4 */
	u8 ucMTx2LOS          : 1; /* masking bit for TX LOS indicator, channel 2 (optional), 100 bit 5 */
	u8 ucMTx3LOS          : 1; /* masking bit for TX LOS indicator, channel 3 (optional), 100 bit 6 */
	u8 ucMTx4LOS          : 1; /* masking bit for TX LOS indicator, channel 4 (optional), 100 bit 7 */

	u8 ucMTx1Fault        : 1; /* masking bit for TX fault indicator, channel 1, 101 bit 0 */
	u8 ucMTx2Fault        : 1; /* masking bit for TX fault indicator, channel 2, 101 bit 1 */
	u8 ucMTx3Fault        : 1; /* masking bit for TX fault indicator, channel 3, 101 bit 2 */
	u8 ucMTx4Fault        : 1; /* masking bit for TX fault indicator, channel 4, 101 bit 3 */
	u8 ucReserverd1       : 4; /* reserved, 101[7:4] */

	u8 ucReserverd2;           /* reserved, 102 */

	u8 ucReserverd3       : 4; /* reserved, 103[3:0] */

	u8 ucMTempWarningLow  : 1; /* masking bit for low temperature warning, 103 bit 4 */
	u8 ucMTempWarningHigh : 1; /* masking bit for high temperature warning, 103 bit 5 */
	u8 ucMTempAlarmLow    : 1; /* masking bit for low temperature alarm, 103 bit 6 */
	u8 ucMTempAlarmHigh   : 1; /* masking bit for high temperature alarm, 103 bit 7 */

	u8 ucReserverd4       : 4; /* reserved, 104[3:0] */

	u8 ucMVccWarningLow   : 1; /* masking bit for low Vcc warning, 104 bit 4 */
	u8 ucMVccWarningHigh  : 1; /* masking bit for high Vcc warning, 104 bit 5 */
	u8 ucMVccAlarmLow     : 1; /* masking bit for low Vcc alarm, 104 bit 6 */
	u8 ucMVccAlarmHigh    : 1; /* masking bit for high Vcc alarm, 104 bit 7 */

	u8 ucReserverd5[2];        /* reserved, 105~106 */
	} stModAndChMasks;

    /* reserved (12 Bytes), offset 107~118 */
	u8 ucReserverd[12];

    /* change entry area (optional) (4 Bytes), offset 119~122 */
	u8 ucChangeEntryArea[4];

    /* entry area (optional) (4 Bytes), offset 123~126 */
	u8 ucEntryArea[4];

    /* page select byte, offset 127 */
	u8 ucPageSelect;
} qsfp_lower_page_s;

/* Page 00h consists of the serial ID and is used for read only identification information.
 * The serial ID is divided into the Base_ID fields, extended ID fields and vendor specific ID fields.
 */
typedef struct {
    /* offset 128~191 */
	struct {
	u8 ucId;                      /* identifier type of serial transceiver */
	u8 ucIdExt;                   /* extended identifier of serial transceiver */
	u8 ucConnector;               /* code for connector type */
	u8 aucTransceiver[8];         /* code for electronic compatibility or optical compatibility */
	u8 ucEncoding;                /* code for serial encoding algorithm */
	u8 ucBrNominal;               /* nominal bit rate, units of 100 MBits/s. */
	u8 ucRateIdentifier;          /* type of rate select functionality */
	u8 ucLengthSmfKm;             /* link length supported for single mode fiber, units of km */
	u8 ucLengthE50um;             /* link length supported for EBW 50/125 um fiber, units of 2 m */
	u8 ucLength50um;              /* link length supported for 50/125 um fiber, units of 1 m */
	u8 ucLength62p5um;            /* link length supported for 62.5/125 um fiber, units of 1 m */
	u8 ucLengthCopper;            /* link length supported for copper, units of 1m */
	u8 ucDeviceTech;              /* device technology */
	u8 aucVendorName[16];         /* ASCII */
	u8 ucExtTransceiver;          /* the extended transceiver codes define the electronic or
				       * optical interfaces for InfiniBand that are supported
				       */
	u8 aucVendorOUI[3];           /* QSFP vendor IEEE company ID */
	u8 aucVendorPN[16];           /* part number provided by QSFP vendor (ASCII) */
	u8 aucVendorRev[2];           /* revision level for part number provided by vendor (ASCII) */
	u8 aucWaveLength[2];          /* nominal laser wavelength (Wavelength = value / 20 in nm) */
	u8 aucWaveLengthTolerance[2]; /* guaranteed range of laser wavelength (+/- value) from nominal
				       * wavelength.(Wavelength Tol. = value/200 in nm)
				       */
	u8 ucMaxCaseTemp;             /* maximum case temperature in degrees C. */
	u8 ucCcBase;                  /* check code for base ID fields (addresses 128-190) */
	} stBaseIdFields;

    /* offset 192~223 */
	struct {
	u8 aucOptions[4];        /* rate select, TX disable, TX fault, LOS */
	u8 aucVendorSN[16];      /* serial number provided by vendor (ASCII) */
	u8 aucDateCode[8];       /* vendor's manufacturing date code */
	u8 ucDiagMonitorType; /* indicate which type of diagnostic monitoring is implemented (if any) in the
			       * transceiver. Bit 1, 0 reserved
			       */
	u8 ucEnhancedOptions;    /* indicate which optional enhanced features are implemented in the transceiver */
	u8 ucBrNominal;
	u8 ucCcExt;              /* check code for the extended ID fields (addresses 192-222) */
	} stExtIdFields;

    /* offset 224~255 */
	struct {
	u8 aucVendorSpecEeprom[32]; /* vendor specific EEPROM */
	} stVendorSpecIdFields;
} qsfp_upper_page0_s;


typedef struct {
	u8 ucCcAPPS;                 /* check code for the AST; the check code shall be the
				      * low order 8 bits of the sum of the contents of all the
				      * bytes from byte 129 to byte 255, inclusive.
				      */
	u8 ucASTTableLength     : 6; /* a 6-bit binary number, TL, specifies how many
				      * application table entries are defined in bytes 130-255
				      * addresses. TL is valid between 0 (1 entry) and 62 (for
				      * a total of 63 entries).
				      */
	u8 ucReserved           : 2; /* reserved 129[7:6] */

	u8 ucApplicationCode0[2];    /* definition of first application supported, offset 130~131 */
	u8 ucOtherTableEntries[122]; /* other table entries, offset 132~253 */
	u8 ucApplicationCodeTL[2];   /* definition of last application supported, 254~255 */
} qsfp_upper_page1_s;

/* Page 02 is optionally provided as user writable EEPROM. The host system may read or write this memory for
 * any purpose. If bit 4 of Page 00 byte 129 is set, however, the first 10 bytes of Table 02h, bytes128-137 will be
 * used to store the CLEI code for the module.
 */
typedef struct {
	u8 aucUserEeprom[128];
} qsfp_upper_page2_s;

/* The upper memory map page 03h contains module thresholds, channel thresholds and masks, and optional
 * channel controls.
 */
typedef struct {
    /* 128~223 */
	struct {
	/* module thresholds (48 Bytes), offset 128~175 */
	u8 aucTempAlarmHigh[2];     /* MSB at low address */
	u8 aucTempAlarmLow[2];      /* MSB at low address */
	u8 aucTempWarningHigh[2];   /* MSB at low address */
	u8 aucTempWarningLow[2];    /* MSB at low address */

	u8 aucReserved1[8];

	u8 aucVccAlarmHigh[2];      /* MSB at low address */
	u8 aucVccAlarmLow[2];       /* MSB at low address */
	u8 aucVccWarningHigh[2];    /* MSB at low address */
	u8 aucVccWarningLow[2];     /* MSB at low address */

	u8 aucReserved2[24];        /* offset 152~175 */

	/* channel thresholds (48 Bytes), 176~223 */
	u8 aucRxPwrAlarmHigh[2];    /* MSB at low address */
	u8 aucRxPwrAlarmLow[2];     /* MSB at low address */
	u8 aucRxPwrWarningHigh[2];  /* MSB at low address */
	u8 aucRxPwrWarningLow[2];   /* MSB at low address */

	u8 aucTxBiasAlarmHigh[2];   /* MSB at low address */
	u8 aucTxBiasAlarmLow[2];    /* MSB at low address */
	u8 aucTxBiasWarningHigh[2]; /* MSB at low address */
	u8 aucTxBiasWarningLow[2];  /* MSB at low address */

	u8 aucTxPwrAlarmHigh[2];    /* MSB at low address */
	u8 aucTxPwrAlarmLow[2];     /* MSB at low address */
	u8 aucTxPwrWarningHigh[2];  /* MSB at low address */
	u8 aucTxPwrWarningLow[2];   /* MSB at low address */

	u8 aucReserved4[8];         /* reserved thresholds for channel parameter set 4 */
	u8 aucReserved5[8];         /* reserved thresholds for channel parameter set 5 */
	u8 aucReserved6[8];         /* reserved thresholds for channel parameter set 6 */
	} stAlarmWarnTh;

    /* 224~225 */
	u8 aucReserved1[2];

    /* 226~239 */
	u8 aucVendorSpecificChannelControls[14]; /* vendor specific channel controls (14 Bytes) */

    /* 240~241 */
	struct {
	u8 ucTx1SQDisable     : 1; /* Tx squelch disable, channel 1 (optional), 240 bit 0 */
	u8 ucTx2SQDisable     : 1; /* Tx squelch disable, channel 2 (optional), 240 bit 1 */
	u8 ucTx3SQDisable     : 1; /* Tx squelch disable, channel 3 (optional), 240 bit 2 */
	u8 ucTx4SQDisable     : 1; /* Tx squelch disable, channel 4 (optional), 240 bit 3 */

	u8 ucRx1SQDisable     : 1; /* Rx squelch disable, channel 1 (optional), 240 bit 4 */
	u8 ucRx2SQDisable     : 1; /* Rx squelch disable, channel 2 (optional), 240 bit 5 */
	u8 ucRx3SQDisable     : 1; /* Rx squelch disable, channel 3 (optional), 240 bit 6 */
	u8 ucRx4SQDisable     : 1; /* Rx squelch disable, channel 4 (optional), 240 bit 7 */

	u8 ucRsvd             : 4; /* reserved 241[3:0] */
	u8 ucRx1OutputDisable : 1; /* Rx output disable, channel 1 (optional), 241 bit 4 */
	u8 ucRx2OutputDisable : 1; /* Rx output disable, channel 2 (optional), 241 bit 5 */
	u8 ucRx3OutputDisable : 1; /* Rx output disable, channel 3 (optional), 241 bit 6 */
	u8 ucRx4OutputDisable : 1; /* Rx output disable, channel 4 (optional), 241 bit 7 */
	} stOptChCtrls;

    /* 242~253 */
	struct {
	/* channel 2 power mointer mask, 242[3:0] */
	u8 ucMRx2PowerWarningLow  : 1; /* masking bit for low RX power warning, channel 2, 242 bit 0 */
	u8 ucMRx2PowerWarningHigh : 1; /* masking bit for high RX power warning, channel 2, 242 bit 1 */
	u8 ucMRx2PowerAlarmLow    : 1; /* masking bit for low RX power alarm, channel 2, 242 bit 2 */
	u8 ucMRx2PowerAlarmHigh   : 1; /* masking bit for high RX power alarm, channel 2, 242 bit 3 */

	/* channel 1 power mointer mask, 242[7:4] */
	u8 ucMRx1PowerWarningLow  : 1; /* masking bit for low RX power warning, channel 1, 242 bit 4 */
	u8 ucMRx1PowerWarningHigh : 1; /* masking bit for high RX power warning, channel 1, 242 bit 5 */
	u8 ucMRx1PowerAlarmLow    : 1; /* masking bit for low RX power alarm, channel 1, 242 bit 6 */
	u8 ucMRx1PowerAlarmHigh   : 1; /* masking bit for high RX power alarm, channel 1, 242 bit 7 */

	/* channel 4 power mointer mask, 243[3:0] */
	u8 ucMRx4PowerWarningLow  : 1; /* masking bit for low RX power warning, channel 4, 243 bit 0 */
	u8 ucMRx4PowerWarningHigh : 1; /* masking bit for high RX power warning, channel 4, 243 bit 1 */
	u8 ucMRx4PowerAlarmLow    : 1; /* masking bit for low RX power alarm, channel 4, 243 bit 2 */
	u8 ucMRx4PowerAlarmHigh   : 1; /* masking bit for high RX power alarm, channel 4, 243 bit 3 */

	/* channel 3 power mointer mask, 243[7:4] */
	u8 ucMRx3PowerWarningLow  : 1; /* masking bit for low RX power warning, channel 3, 243 bit 4 */
	u8 ucMRx3PowerWarningHigh : 1; /* masking bit for high RX power warning, channel 3, 243 bit 5 */
	u8 ucMRx3PowerAlarmLow    : 1; /* masking bit for low RX power alarm, channel 3, 243 bit 6 */
	u8 ucMRx3PowerAlarmHigh   : 1; /* masking bit for high RX power alarm, channel 3, 243 bit 7 */

	/* channel 2 Bias mointer mask, 244[3:0] */
	u8 ucMTx2BiasWarningLow   : 1; /* masking bit for low TX bias warning, channel 2, 244 bit 0 */
	u8 ucMTx2BiasWarningHigh  : 1; /* masking bit for low TX bias warning, channel 2, 244 bit 1 */
	u8 ucMTx2BiasAlarmLow     : 1; /* masking bit for low TX bias alarm, channel 2, 244 bit 2 */
	u8 ucMTx2BiasAlarmHigh    : 1; /* masking bit for high TX bias alarm, channel 2, 244 bit 3 */

	/* channel 1 Bias mointer mask, 244[7:4] */
	u8 ucMTx1BiasWarningLow   : 1; /* masking bit for low TX bias warning, channel 1, 244 bit 4 */
	u8 ucMTx1BiasWarningHigh  : 1; /* masking bit for low TX bias warning, channel 1, 244 bit 5 */
	u8 ucMTx1BiasAlarmLow     : 1; /* masking bit for low TX bias alarm, channel 1, 244 bit 6 */
	u8 ucMTx1BiasAlarmHigh    : 1; /* masking bit for high TX bias alarm, channel 1, 244 bit 7 */

	/* channel 4 Bias mointer mask, 245[3:0] */
	u8 ucMTx4BiasWarningLow   : 1; /* masking bit for low TX bias warning, channel 4, 245 bit 0 */
	u8 ucMTx4BiasWarningHigh  : 1; /* masking bit for low TX bias warning, channel 4, 245 bit 1 */
	u8 ucMTx4BiasAlarmLow     : 1; /* masking bit for low TX bias alarm, channel 4, 245 bit 2 */
	u8 ucMTx4BiasAlarmHigh    : 1; /* masking bit for high TX bias alarm, channel 4, 245 bit 3 */

	/* channel 3 Bias mointer mask, 245[7:4] */
	u8 ucMTx3BiasWarningLow   : 1; /* masking bit for low TX bias warning, channel 3, 245 bit 4 */
	u8 ucMTx3BiasWarningHigh  : 1; /* masking bit for low TX bias warning, channel 3, 245 bit 5 */
	u8 ucMTx3BiasAlarmLow     : 1; /* masking bit for low TX bias alarm, channel 3, 245 bit 6 */
	u8 ucMTx3BiasAlarmHigh    : 1; /* masking bit for high TX bias alarm, channel 3, 245 bit 7 */

	u8 ucReserverd1[2];            /* reserved channel monitor masks, set 3 */
	u8 ucReserverd2[2];            /* reserved channel monitor masks, set 4 */
	u8 ucReserverd3[2];            /* reserved channel monitor masks, set 5 */
	u8 ucReserverd4[2];            /* reserved channel monitor masks, set 6 */
	} stChMtMasks;

    /* reserved, offset 254~255 */
	u8 aucReserved2[2]; /* reserved (2 Bytes) */
} qsfp_upper_page3_s;

/* QSFP has a total of 640-byte data structures
 * low-end 128 bytes, high-end 4 pages, each page 128 bytes, high-end 512 bytes total
 */
struct qsfp_info_t {
	qsfp_lower_page_s qsfp_low_page; /* QSFP lower 128-byte data */
	qsfp_upper_page0_s qsfp_high_page_0;       /* QSFP high-end page 00 128-byte data */
	qsfp_upper_page1_s qsfp_high_page_1;       /* QSFP high-end page 01 128-byte data */
	qsfp_upper_page2_s qsfp_high_page_2;       /* QSFP high-end page 02 128-byte data */
	qsfp_upper_page3_s qsfp_high_page_3;       /* QSFP high-end page 03 128-byte data */
};

#endif // EEPROM_QSFP_DEFS_H
