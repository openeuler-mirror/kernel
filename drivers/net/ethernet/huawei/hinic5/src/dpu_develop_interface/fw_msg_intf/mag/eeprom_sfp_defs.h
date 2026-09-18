/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : eeprom_sfp_defs.h
 * Version       : Initial Draft
 * Created       : 2024-04-13
 * Last Modified : 2026/09/16
 * Description   : sfp data definition
 */

#ifndef EEPROM_SFP_DEFS_H
#define EEPROM_SFP_DEFS_H

typedef struct tagSfpDataFieldA0_S {
    /* 0~63 */
	struct {
	u8 ucId;
	u8 ucIdExt;
	u8 ucConnector;
	u8 aucTransceiver[8];
	u8 ucEncoding;
	u8 ucBrNominal;       /* nominal signalling rate, units of 100MBd. */
	u8 ucRateIdentifier;  /* type of rate select functionality */
	u8 ucLengthSmfKm;     /* link length supported for single mode fiber, units of km */
	u8 ucLengthSmf;       /* link length supported for single mode fiber, units of 100 m */
	u8 ucLengthSmfOm2;    /* link length supported for 50 um OM2 fiber, units of 10 m */
	u8 ucLengthSmfOm1;    /* link length supported for 62.5 um OM1 fiber, units of 10 m */
	u8 ucLengthCable;     /* link length supported for copper or direct attach cable, units of m */
	u8 ucLengthOm3;       /* link length supported for 50 um OM3 fiber, units of 10 m */
	u8 aucVendorName[16]; /* ASCII */
	u8 ucTransceiver;     /* code for electronic or optical compatibility */
	u8 aucVendorOui[3];   /* SFP vendor IEEE company ID */
	u8 aucVendorPn[16];   /* part number provided by SFP vendor (ASCII) */
	u8 aucVendorRev[4];   /* revision level for part number provided by vendor (ASCII) */
	u8 aucWaveLength[2];  /* laser wavelength (passive/active cable specification compliance) */
	u8 ucUnAllocated;
	u8 ucCcBase;          /* check code for base ID fields (addresses 0 to 62) */
	} stBaseIdFields;

    /* 64~95 */
	struct {
	u8 aucOptions[2];
	u8 ucBrMax;
	u8 ucBrMin;
	u8 aucVendorSn[16];
	u8 aucDateCode[8];
	u8 ucDiagMonitorType;
	u8 ucEnhancedOptions;
	u8 ucSff8472Compliance;
	u8 ucCcExt;
	} stExtIdFields;

    /* 96~255 */
	struct {
	u8 aucVendorSpecEeprom[32];
	u8 aucRsvd[128];
	} stVendorSpecIdFields;
} SfpDataFieldA0_S;

#define ELABEL_BOM_SIZE                   14
#define ITEM_CHECK_SUM_SIZE               2
#define ELABEL_BOM_EXT_SIZE               3

/* SFP electronic label item format */
typedef struct tagSfp_elabel_item {
	u8 bom[ELABEL_BOM_SIZE];            /* 14bytes bom zone */
	u8 check_sum0[ITEM_CHECK_SUM_SIZE]; /* 2bytes checksum1 */
	u8 bom_ext[ELABEL_BOM_EXT_SIZE];    /* 3bytes extended bom zone */
	u8 check_sum1[ITEM_CHECK_SUM_SIZE]; /* 2byts checksum2 */
} Sfp_elabel_item_t;

/* user region format of the SFP page A2 register, electronic labels occupy part of the space in the zone */
typedef struct tagSfp_a2_usr_region {
	u8 reserve0[16];
	Sfp_elabel_item_t item; /* 21-byte item code */
	u8 reserve1[6];
	u8 model[40];           /* 40-byte model field */
	u8 rev[6];              /* 6-byte rev field */
	u8 reserve2[27];
	u8 check_sum;           /* 1-byte verification, used to verify stdver and stdtype */
	u8 std_ver;             /* electronic label version */
	u8 std_type[2];         /* electronic label storage format */
} Sfp_a2_usr_region_t;

typedef struct tagSfpDataFieldA2_S {
    /* 0~119 */
	struct {
	/* 0~39 */
	struct {
		u8 aucTempAlarmHigh[2];
		u8 aucTempAlarmLow[2];
		u8 aucTempWarningHigh[2];
		u8 aucTempWarningLow[2];

		u8 aucVccAlarmHigh[2];
		u8 aucVccAlarmLow[2];
		u8 aucVccWarningHigh[2];
		u8 aucVccWarningLow[2];

		u8 aucBiasAlarmHigh[2];
		u8 aucBiasAlarmLow[2];
		u8 aucBiasWarningHigh[2];
		u8 aucBiasWarningLow[2];

		u8 aucTxAlarmHigh[2];
		u8 aucTxAlarmLow[2];
		u8 aucTxWarningHigh[2];
		u8 aucTxWarningLow[2];

		u8 aucRxAlarmHigh[2];
		u8 aucRxAlarmLow[2];
		u8 aucRxWarningHigh[2];
		u8 aucRxWarningLow[2];
	} stAlarmWarnTh;

	/* 40~95 */
	u8 aucUnAllocated0[16];
	u8 aucExtCalConstants[36];
	u8 aucUnAllocated1[3];
	u8 ucCcDmi;

	/* 96~105 */
	struct {
		u8 aucTemp[2];
		u8 aucVcc[2];
		u8 aucTxBias[2];
		u8 aucTxPower[2];
		u8 aucRxPower[2];
	} stDiag;

	/* 106~109 */
	u8 aucUnAllocated2[4];

	/* 110 */
	union {
		struct {
		u8 ucDataRdyBarState     : 1;
		u8 ucRxLos               : 1;
		u8 ucTxFaultState        : 1;
		u8 ucSoftRateSelectState : 1;
		u8 ucRateSelectState     : 1;
		u8 ucRsState             : 1;
		u8 ucSoftTxDisableSelect : 1;
		u8 ucTxDisableState      : 1;
		} bits;
		u8 value;
	} stStatusCtrl;
	/* 111 */
	u8 ucRsvd;

	/* 112~113 */
	struct {
		/* 112 */
		u8 ucTxAlarmLow      : 1;
		u8 ucTxAlarmHigh     : 1;
		u8 ucTxBiasAlarmLow  : 1;
		u8 ucTxBiasAlarmHigh : 1;
		u8 ucVccAlarmLow     : 1;
		u8 ucVccAlarmHigh    : 1;
		u8 ucTempAlarmLow    : 1;
		u8 ucTempAlarmHigh   : 1;

		/* 113 */
		u8 ucRsvd            : 6;
		u8 ucRxAlarmLow      : 1;
		u8 ucRxAlarmHigh     : 1;
	} stAlarm;

	/* 114~115 */
	u8 aucUnAllocated3[2];

	/* 116~117 */
	struct {
		/* 116 */
		u8 ucTxWarnLo   : 1;
		u8 ucTxWarnHi   : 1;
		u8 ucBiasWarnLo : 1;
		u8 ucBiasWarnHi : 1;
		u8 ucVccWarnLo  : 1;
		u8 ucVccWarnHi  : 1;
		u8 ucTempWarnLo : 1;
		u8 ucTempWarnHi : 1;

		/* 117 */
		u8 ucRsvd       : 6;
		u8 ucRxWarnLo   : 1;
		u8 ucRxWarnHi   : 1;
	} stWarning;

	/* 118~119 */
	u8 aucExtStatusAndCtrl[2];
	} stDiag;

    /* 120~255 */
	struct {
	u8 aucVendorSpec[8];
	Sfp_a2_usr_region_t aucUserEeprom;
	u8 aucVendorCtrl[8];
	} stGeneralUseFields;
} SfpDataFieldA2_S;

/* SFP structure used in standard SFF-8472 Rev 10.4 */
typedef struct tagSfpInfo_S {
	SfpDataFieldA0_S stSfpInfoA0;
	SfpDataFieldA2_S stSfpInfoA2;
} SfpInfo_S;

typedef SfpDataFieldA0_S tag_ncsi_sfp_data_fielda0;
typedef SfpDataFieldA2_S tag_ncsi_sfp_data_fielda2;

#endif // EEPROM_SFP_DEFS_H
