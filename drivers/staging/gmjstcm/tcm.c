// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2009 Nationz Technologies Inc.
 *
 * Description: Exprot symbol for tcm_tis module
 *
 * Major Function: public write read register function etc.
 *
 */

#include <linux/sched.h>
#include <linux/poll.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include "tcm.h"

/*
 * const var
 */
enum tcm_const {
	TCM_MINOR = 224,	/* officially assigned */
	TCM_BUFSIZE = 2048,	/* Buffer Size */
	TCM_NUM_DEVICES = 256,	/* Max supporting tcm device number */
};

/*
 * CMD duration
 */
enum tcm_duration {
	TCM_SHORT = 0,
	TCM_MEDIUM = 1,
	TCM_LONG = 2,
	TCM_UNDEFINED,
};

/* Max Total of Command Number */
#define TCM_MAX_ORDINAL 88 /*243*/

static LIST_HEAD(tcm_chip_list);
static DEFINE_SPINLOCK(driver_lock); /* spin lock */
static DECLARE_BITMAP(dev_mask, TCM_NUM_DEVICES);

typedef struct tagTCM_Command {
	u8 ordinal;
	u8 DURATION;
} TCM_Command;

static const TCM_Command TCM_Command_List[TCM_MAX_ORDINAL + 1] = {
	{/*TCM_ORD_ActivateIdentity,		*/122,	1},
	{/*TCM_ORD_CertifyKey,			*/50,	1},
	{/*TCM_ORD_CertifyKeyM,			*/51,	1},
	{/*TCM_ORD_ChangeAuth,			*/12,	1},
	{/*TCM_ORD_ChangeAuthOwner,		*/16,	0},
	{/*TCM_ORD_ContinueSelfTeSt,		*/83,	2},
	{/*TCM_ORD_CreateCounter,		*/220,	0},
	{/*TCM_ORD_CreateWrapKey,		*/31,	2},
	{/*TCM_ORD_DiSableForceClear,		*/94,	0},
	{/*TCM_ORD_DiSableOwnerClear,		*/92,	0},
	{/*TCM_ORD_EStabliShTranSport,		*/230,	0},
	{/*TCM_ORD_ExecuteTranSport,		*/231,	2},
	{/*TCM_ORD_Extend,			*/20,	0},
	{/*TCM_ORD_FieldUpgrade,		*/170,	2},
	{/*TCM_ORD_FluShSpecific,		*/186,	0},
	{/*TCM_ORD_ForceClear,			*/93,	0},
	{/*TCM_ORD_GetAuditDigeSt,		*/133,	0},
	{/*TCM_ORD_GetAuditDigeStSigned,	*/134,	1},
	{/*TCM_ORD_GetCapability,		*/101,	0},
	{/*TCM_ORD_GetPubKey,			*/33,	0},
	{/*TCM_ORD_GetRandoM,			*/70,	0},
	{/*TCM_ORD_GetTeStReSult,		*/84,	0},
	{/*TCM_ORD_GetTickS,			*/241,	0},
	{/*TCM_ORD_IncreMentCounter,		*/221,	0},
	{/*TCM_ORD_LoadContext,			*/185,	1},
	{/*TCM_ORD_MakeIdentity,		*/121,	2},
	{/*TCM_ORD_NV_DefineSpace,		*/204,	0},
	{/*TCM_ORD_NV_ReadValue,		*/207,	0},
	{/*TCM_ORD_NV_ReadValueAuth,		*/208,	0},
	{/*TCM_ORD_NV_WriteValue,		*/205,	0},
	{/*TCM_ORD_NV_WriteValueAuth,		*/206,	0},
	{/*TCM_ORD_OwnerClear,			*/91,	0},
	{/*TCM_ORD_OwnerReadInternalPub,	*/129,	0},
	{/*TCM_ORD_OwnerSetDiSable,		*/110,	0},
	{/*TCM_ORD_PCR_ReSet,			*/200,	0},
	{/*TCM_ORD_PcrRead,			*/21,	0},
	{/*TCM_ORD_PhySicalDiSable,		*/112,	0},
	{/*TCM_ORD_PhySicalEnable,		*/111,	0},
	{/*TCM_ORD_PhySicalSetDeactivated,	*/114,	0},
	{/*TCM_ORD_Quote,			*/22,	1},
	{/*TCM_ORD_QuoteM,			*/62,	1},
	{/*TCM_ORD_ReadCounter,			*/222,	0},
	{/*TCM_ORD_ReadPubek,			*/124,	0},
	{/*TCM_ORD_ReleaSeCounter,		*/223,	0},
	{/*TCM_ORD_ReleaSeCounterOwner,		*/224,	0},
	{/*TCM_ORD_ReleaSeTranSportSigned,	*/232,	1},
	{/*TCM_ORD_ReSetLockValue,		*/64,	0},
	{/*TCM_ORD_RevokeTruSt,			*/128,	0},
	{/*TCM_ORD_SaveContext,			*/184,	1},
	{/*TCM_ORD_SaveState,			*/152,	1},
	{/*TCM_ORD_Seal,			*/23,	1},
	{/*TCM_ORD_Sealx,			*/61,	1},
	{/*TCM_ORD_SelfTeStFull,		*/80,	2},
	{/*TCM_ORD_SetCapability,		*/63,	0},
	{/*TCM_ORD_SetOperatorAuth,		*/116,	0},
	{/*TCM_ORD_SetOrdinalAuditStatuS,	*/141,	0},
	{/*TCM_ORD_SetOwnerInStall,		*/113,	0},
	{/*TCM_ORD_SetTeMpDeactivated,		*/115,	0},
	{/*TCM_ORD_Sign,			*/60,	1},
	{/*TCM_ORD_Startup,			*/153,	0},
	{/*TCM_ORD_TakeOwnerShip,		*/13,	1},
	{/*TCM_ORD_TickStaMpBlob,		*/242,	1},
	{/*TCM_ORD_UnSeal,			*/24,	1},
	{/*TSC_ORD_PhySicalPreSence,		*/10,	0},
	{/*TSC_ORD_ReSetEStabliShMentBit,	*/11,	0},
	{/*TCM_ORD_WrapKey,			*/189,	2},
	{/*TCM_ORD_APcreate,			*/191,	0},
	{/*TCM_ORD_APTerMinate,			*/192,	0},
	{/*TCM_ORD_CreateMigratedBlob,		*/193,	1},
	{/*TCM_ORD_ConvertMigratedBlob,		*/194,	1},
	{/*TCM_ORD_AuthorizeMigrationKey,	*/195,	0},
	{/*TCM_ORD_SMS4Encrypt,			*/197,	1},
	{/*TCM_ORD_SMS4Decrypt,			*/198,	1},
	{/*TCM_ORD_ReadEKCert,			*/199,	1},
	{/*TCM_ORD_WriteEKCert,			*/233,	1},
	{/*TCM_ORD_SCHStart,			*/234,	0},
	{/*TCM_ORD_SCHUpdata,			*/235,	0},
	{/*TCM_ORD_SCHCoMplete,			*/236,	0},
	{/*TCM_ORD_SCHCoMpleteExtend,		*/237,	0},
	{/*TCM_ORD_ECCDecrypt,			*/238,	1},
	{/*TCM_ORD_LoadKey,			*/239,	1},
	{/*TCM_ORD_CreateEndorSeMentKeyPair,	*/120,	2},
	{/*TCM_ORD_CreateRevocableEK,		*/127,	2},
	{/*TCM_ORD_ReleaSeECCExchangeSeSSion,	*/174,	1},
	{/*TCM_ORD_CreateECCExchangeSeSSion,	*/175,	1},
	{/*TCM_ORD_GetKeyECCExchangeSeSSion,	*/176,	1},
	{/*TCM_ORD_ActivatePEK,			*/217,	1},
	{/*TCM_ORD_ActivatePEKCert,		*/218,	1},
	{0,	0}
};

static void user_reader_timeout(struct timer_list *t)
{
	struct tcm_chip *chip = from_timer(chip, t, user_read_timer);

	schedule_work(&chip->work);
}

static void timeout_work(struct work_struct *work)
{
	struct tcm_chip *chip = container_of(work, struct tcm_chip, work);

	mutex_lock(&chip->buffer_mutex);
	atomic_set(&chip->data_pending, 0);
	memset(chip->data_buffer, 0, TCM_BUFSIZE);
	mutex_unlock(&chip->buffer_mutex);
}

unsigned long tcm_calc_ordinal_duration(struct tcm_chip *chip,
					   u32 ordinal)
{
	int duration_idx = TCM_UNDEFINED;
	int duration = 0;
	int i = 0;

	for (i = 0; i < TCM_MAX_ORDINAL; i++) {
		if (ordinal == TCM_Command_List[i].ordinal) {
			duration_idx = TCM_Command_List[i].DURATION;
			break;
		}
	}

	if (duration_idx != TCM_UNDEFINED)
		duration = chip->vendor.duration[duration_idx];
	if (duration <= 0)
		return 2 * 60 * HZ;
	else
		return duration;
}
EXPORT_SYMBOL_GPL(tcm_calc_ordinal_duration);

/*
 * Internal kernel interface to transmit TCM commands
 * buff format: TAG(2 bytes) + Total Size(4 bytes ) +
 * Command Ordinal(4 bytes ) + ......
 */
static ssize_t tcm_transmit(struct tcm_chip *chip, const char *buf,
			    size_t bufsiz)
{
	ssize_t rc = 0;
	u32 count = 0, ordinal = 0;
	unsigned long stop = 0;

	count = be32_to_cpu(*((__be32 *)(buf + 2))); /* buff size */
	ordinal = be32_to_cpu(*((__be32 *)(buf + 6))); /* command ordinal */

	if (count == 0)
		return -ENODATA;
	if (count > bufsiz) { /* buff size err ,invalid buff stream */
		dev_err(chip->dev, "invalid count value %x, %zx\n",
				count, bufsiz);
		return -E2BIG;
	}

	mutex_lock(&chip->tcm_mutex); /* enter mutex */

	rc = chip->vendor.send(chip, (u8 *)buf, count);
	if (rc < 0) {
		dev_err(chip->dev, "%s: tcm_send: error %zd\n",
				__func__, rc);
		goto out;
	}

	if (chip->vendor.irq)
		goto out_recv;

	stop = jiffies + tcm_calc_ordinal_duration(chip,
			ordinal); /* cmd duration */
	do {
		u8 status = chip->vendor.status(chip);

		if ((status & chip->vendor.req_complete_mask) ==
				chip->vendor.req_complete_val)
			goto out_recv;

		if ((status == chip->vendor.req_canceled)) {
			dev_err(chip->dev, "Operation Canceled\n");
			rc = -ECANCELED;
			goto out;
		}

		msleep(TCM_TIMEOUT); /* CHECK */
		rmb();
	} while (time_before(jiffies, stop));
	/* time out */
	chip->vendor.cancel(chip);
	dev_err(chip->dev, "Operation Timed out\n");
	rc = -ETIME;
	goto out;

out_recv:
	rc = chip->vendor.recv(chip, (u8 *)buf, bufsiz);
	if (rc < 0)
		dev_err(chip->dev, "%s: tcm_recv: error %zd\n",
				__func__, rc);
out:
	mutex_unlock(&chip->tcm_mutex);
	return rc;
}

#define TCM_DIGEST_SIZE 32
#define TCM_ERROR_SIZE 10
#define TCM_RET_CODE_IDX 6
#define TCM_GET_CAP_RET_SIZE_IDX 10
#define TCM_GET_CAP_RET_UINT32_1_IDX 14
#define TCM_GET_CAP_RET_UINT32_2_IDX 18
#define TCM_GET_CAP_RET_UINT32_3_IDX 22
#define TCM_GET_CAP_RET_UINT32_4_IDX 26
#define TCM_GET_CAP_PERM_DISABLE_IDX 16
#define TCM_GET_CAP_PERM_INACTIVE_IDX 18
#define TCM_GET_CAP_RET_BOOL_1_IDX 14
#define TCM_GET_CAP_TEMP_INACTIVE_IDX 16

#define TCM_CAP_IDX 13
#define TCM_CAP_SUBCAP_IDX 21

enum tcm_capabilities {
	TCM_CAP_FLAG = 4,
	TCM_CAP_PROP = 5,
};

enum tcm_sub_capabilities {
	TCM_CAP_PROP_PCR = 0x1,			/* tcm 0x101 */
	TCM_CAP_PROP_MANUFACTURER = 0x3,	/* tcm 0x103 */
	TCM_CAP_FLAG_PERM = 0x8,		/* tcm 0x108 */
	TCM_CAP_FLAG_VOL = 0x9,			/* tcm 0x109 */
	TCM_CAP_PROP_OWNER = 0x11,		/* tcm 0x101 */
	TCM_CAP_PROP_TIS_TIMEOUT = 0x15,	/* tcm 0x115 */
	TCM_CAP_PROP_TIS_DURATION = 0x20,	/* tcm 0x120 */
};

/*
 * This is a semi generic GetCapability command for use
 * with the capability type TCM_CAP_PROP or TCM_CAP_FLAG
 * and their associated sub_capabilities.
 */

static const u8 tcm_cap[] = {
	0, 193,			/* TCM_TAG_RQU_COMMAND 0xc1*/
	0, 0, 0, 22,		/* length */
	0, 0, 128, 101,		/* TCM_ORD_GetCapability */
	0, 0, 0, 0,		/* TCM_CAP_<TYPE> */
	0, 0, 0, 4,		/* TCM_CAP_SUB_<TYPE> size */
	0, 0, 1, 0		/* TCM_CAP_SUB_<TYPE> */
};

static ssize_t transmit_cmd(struct tcm_chip *chip, u8 *data, int len,
		char *desc)
{
	int err = 0;

	len = tcm_transmit(chip, data, len);
	if (len <  0)
		return len;
	if (len == TCM_ERROR_SIZE) {
		err = be32_to_cpu(*((__be32 *)(data + TCM_RET_CODE_IDX)));
		dev_dbg(chip->dev, "A TCM error (%d) occurred %s\n", err, desc);
		return err;
	}
	return 0;
}

/*
 * Get default timeouts value form tcm by GetCapability with TCM_CAP_PROP_TIS_TIMEOUT prop
 */
void tcm_get_timeouts(struct tcm_chip *chip)
{
	u8 data[max_t(int, ARRAY_SIZE(tcm_cap), 30)];
	ssize_t rc = 0;
	u32 timeout = 0;

	memcpy(data, tcm_cap, sizeof(tcm_cap));
	data[TCM_CAP_IDX] = TCM_CAP_PROP;
	data[TCM_CAP_SUBCAP_IDX] = TCM_CAP_PROP_TIS_TIMEOUT;

	rc = transmit_cmd(chip, data, sizeof(data),
			"attempting to determine the timeouts");
	if (rc)
		goto duration;

	if (be32_to_cpu(*((__be32 *)(data + TCM_GET_CAP_RET_SIZE_IDX))) !=
			4 * sizeof(u32))
		goto duration;

	/* Don't overwrite default if value is 0 */
	timeout = be32_to_cpu(*((__be32 *)(data + TCM_GET_CAP_RET_UINT32_1_IDX)));
	if (timeout)
		chip->vendor.timeout_a = msecs_to_jiffies(timeout);
	timeout = be32_to_cpu(*((__be32 *)(data + TCM_GET_CAP_RET_UINT32_2_IDX)));
	if (timeout)
		chip->vendor.timeout_b = msecs_to_jiffies(timeout);
	timeout = be32_to_cpu(*((__be32 *)(data + TCM_GET_CAP_RET_UINT32_3_IDX)));
	if (timeout)
		chip->vendor.timeout_c = msecs_to_jiffies(timeout);
	timeout = be32_to_cpu(*((__be32 *)(data + TCM_GET_CAP_RET_UINT32_4_IDX)));
	if (timeout)
		chip->vendor.timeout_d = msecs_to_jiffies(timeout);

duration:
	memcpy(data, tcm_cap, sizeof(tcm_cap));
	data[TCM_CAP_IDX] = TCM_CAP_PROP;
	data[TCM_CAP_SUBCAP_IDX] = TCM_CAP_PROP_TIS_DURATION;

	rc = transmit_cmd(chip, data, sizeof(data),
			"attempting to determine the durations");
	if (rc)
		return;

	if (be32_to_cpu(*((__be32 *)(data + TCM_GET_CAP_RET_SIZE_IDX))) !=
			3 * sizeof(u32))
		return;

	chip->vendor.duration[TCM_SHORT] =
			msecs_to_jiffies(be32_to_cpu(*((__be32 *)(data +
				TCM_GET_CAP_RET_UINT32_1_IDX))));
	chip->vendor.duration[TCM_MEDIUM] =
			msecs_to_jiffies(be32_to_cpu(*((__be32 *)(data +
				TCM_GET_CAP_RET_UINT32_2_IDX))));
	chip->vendor.duration[TCM_LONG] =
			msecs_to_jiffies(be32_to_cpu(*((__be32 *)(data +
				TCM_GET_CAP_RET_UINT32_3_IDX))));
}
EXPORT_SYMBOL_GPL(tcm_get_timeouts);

ssize_t tcm_show_enabled(struct device *dev, struct device_attribute *attr,
		char *buf)
{
	u8 data[max_t(int, ARRAY_SIZE(tcm_cap), 35)];
	ssize_t rc = 0;
	struct tcm_chip *chip = dev_get_drvdata(dev);

	if (chip == NULL)
		return -ENODEV;

	memcpy(data, tcm_cap, sizeof(tcm_cap));
	data[TCM_CAP_IDX] = TCM_CAP_FLAG;
	data[TCM_CAP_SUBCAP_IDX] = TCM_CAP_FLAG_PERM;

	rc = transmit_cmd(chip, data, sizeof(data),
			"attemtping to determine the permanent state");
	if (rc)
		return 0;
	if (data[TCM_GET_CAP_PERM_DISABLE_IDX])
		return sprintf(buf, "disable\n");
	else
		return sprintf(buf, "enable\n");
}
EXPORT_SYMBOL_GPL(tcm_show_enabled);

ssize_t tcm_show_active(struct device *dev, struct device_attribute *attr,
		char *buf)
{
	u8 data[max_t(int, ARRAY_SIZE(tcm_cap), 35)];
	ssize_t rc = 0;
	struct tcm_chip *chip = dev_get_drvdata(dev);

	if (chip == NULL)
		return -ENODEV;

	memcpy(data, tcm_cap, sizeof(tcm_cap));
	data[TCM_CAP_IDX] = TCM_CAP_FLAG;
	data[TCM_CAP_SUBCAP_IDX] = TCM_CAP_FLAG_PERM;

	rc = transmit_cmd(chip, data, sizeof(data),
			"attemtping to determine the permanent state");
	if (rc)
		return 0;
	if (data[TCM_GET_CAP_PERM_INACTIVE_IDX])
		return sprintf(buf, "deactivated\n");
	else
		return sprintf(buf, "activated\n");
}
EXPORT_SYMBOL_GPL(tcm_show_active);

ssize_t tcm_show_owned(struct device *dev, struct device_attribute *attr,
		char *buf)
{
	u8 data[sizeof(tcm_cap)];
	ssize_t rc = 0;
	struct tcm_chip *chip = dev_get_drvdata(dev);

	if (chip == NULL)
		return -ENODEV;

	memcpy(data, tcm_cap, sizeof(tcm_cap));
	data[TCM_CAP_IDX] = TCM_CAP_PROP;
	data[TCM_CAP_SUBCAP_IDX] = TCM_CAP_PROP_OWNER;

	rc = transmit_cmd(chip, data, sizeof(data),
			"attempting to determine the owner state");
	if (rc)
		return 0;
	if (data[TCM_GET_CAP_RET_BOOL_1_IDX])
		return sprintf(buf, "Owner installed\n");
	else
		return sprintf(buf, "Owner have not installed\n");
}
EXPORT_SYMBOL_GPL(tcm_show_owned);

ssize_t tcm_show_temp_deactivated(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	u8 data[sizeof(tcm_cap)];
	ssize_t rc = 0;
	struct tcm_chip *chip = dev_get_drvdata(dev);

	if (chip == NULL)
		return -ENODEV;

	memcpy(data, tcm_cap, sizeof(tcm_cap));
	data[TCM_CAP_IDX] = TCM_CAP_FLAG;
	data[TCM_CAP_SUBCAP_IDX] = TCM_CAP_FLAG_VOL;

	rc = transmit_cmd(chip, data, sizeof(data),
			"attempting to determine the temporary state");
	if (rc)
		return 0;
	if (data[TCM_GET_CAP_TEMP_INACTIVE_IDX])
		return sprintf(buf, "Temp deactivated\n");
	else
		return sprintf(buf, "activated\n");
}
EXPORT_SYMBOL_GPL(tcm_show_temp_deactivated);

static const u8 pcrread[] = {
	0, 193,			/* TCM_TAG_RQU_COMMAND */
	0, 0, 0, 14,		/* length */
	0, 0, 128, 21,		/* TCM_ORD_PcrRead */
	0, 0, 0, 0		/* PCR index */
};

ssize_t tcm_show_pcrs(struct device *dev, struct device_attribute *attr,
		      char *buf)
{
	u8 data[1024];
	ssize_t rc = 0;
	int i = 0, j = 0, num_pcrs = 0;
	__be32 index = 0;
	char *str = buf;
	struct tcm_chip *chip = dev_get_drvdata(dev);

	if (chip == NULL)
		return -ENODEV;

	memcpy(data, tcm_cap, sizeof(tcm_cap));
	data[TCM_CAP_IDX] = TCM_CAP_PROP;
	data[TCM_CAP_SUBCAP_IDX] = TCM_CAP_PROP_PCR;

	rc = transmit_cmd(chip, data, sizeof(data),
			"attempting to determine the number of PCRS");
	if (rc)
		return 0;

	num_pcrs = be32_to_cpu(*((__be32 *)(data + 14)));
	for (i = 0; i < num_pcrs; i++) {
		memcpy(data, pcrread, sizeof(pcrread));
		index = cpu_to_be32(i);
		memcpy(data + 10, &index, 4);
		rc = transmit_cmd(chip, data, sizeof(data),
				"attempting to read a PCR");
		if (rc)
			goto out;
		str += sprintf(str, "PCR-%02d: ", i);
		for (j = 0; j < TCM_DIGEST_SIZE; j++)
			str += sprintf(str, "%02X ", *(data + 10 + j));
		str += sprintf(str, "\n");
		memset(data, 0, 1024);
	}
out:
	return str - buf;
}
EXPORT_SYMBOL_GPL(tcm_show_pcrs);

#define  READ_PUBEK_RESULT_SIZE 128
static const u8 readpubek[] = {
	0, 193,			/* TCM_TAG_RQU_COMMAND */
	0, 0, 0, 42,		/* length */
	0, 0, 128, 124,		/* TCM_ORD_ReadPubek */
	0, 0, 0, 0, 0, 0, 0, 0,	/* NONCE */
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0
};

ssize_t tcm_show_pubek(struct device *dev, struct device_attribute *attr,
		char *buf)
{
	u8 data[READ_PUBEK_RESULT_SIZE] = {0};
	ssize_t err = 0;
	int i = 0, rc = 0;
	char *str = buf;
	struct tcm_chip *chip = dev_get_drvdata(dev);

	if (chip == NULL)
		return -ENODEV;

	memcpy(data, readpubek, sizeof(readpubek));

	err = transmit_cmd(chip, data, sizeof(data),
			"attempting to read the PUBEK");
	if (err)
		goto out;

	str += sprintf(str, "PUBEK:");
	for (i = 0 ; i < 65 ; i++) {
		if ((i) % 16 == 0)
			str += sprintf(str, "\n");
		str += sprintf(str, "%02X  ", data[i+10]);
	}

	str += sprintf(str, "\n");
out:
	rc = str - buf;
	return rc;
}
EXPORT_SYMBOL_GPL(tcm_show_pubek);

#define CAP_VERSION_1_1 6
#define CAP_VERSION_1_2 0x1A
#define CAP_VERSION_IDX 13
static const u8 cap_version[] = {
	0, 193,			/* TCM_TAG_RQU_COMMAND */
	0, 0, 0, 18,		/* length */
	0, 0, 128, 101,		/* TCM_ORD_GetCapability */
	0, 0, 0, 0,
	0, 0, 0, 0
};

ssize_t tcm_show_caps(struct device *dev, struct device_attribute *attr,
		      char *buf)
{
	u8 data[max_t(int, max(ARRAY_SIZE(tcm_cap), ARRAY_SIZE(cap_version)), 30)];
	ssize_t rc = 0;
	char *str = buf;
	struct tcm_chip *chip = dev_get_drvdata(dev);

	if (chip == NULL)
		return -ENODEV;

	memcpy(data, tcm_cap, sizeof(tcm_cap));
	data[TCM_CAP_IDX] = TCM_CAP_PROP;
	data[TCM_CAP_SUBCAP_IDX] = TCM_CAP_PROP_MANUFACTURER;

	rc = transmit_cmd(chip, data, sizeof(data),
			"attempting to determine the manufacturer");
	if (rc)
		return 0;

	str += sprintf(str, "Manufacturer: 0x%x\n",
			be32_to_cpu(*((__be32 *)(data + TCM_GET_CAP_RET_UINT32_1_IDX))));

	memcpy(data, cap_version, sizeof(cap_version));
	data[CAP_VERSION_IDX] = CAP_VERSION_1_1;
	rc = transmit_cmd(chip, data, sizeof(data),
			"attempting to determine the 1.1 version");
	if (rc)
		goto out;

	str += sprintf(str, "Firmware version: %02X.%02X.%02X.%02X\n",
		       (int)data[14], (int)data[15], (int)data[16],
		       (int)data[17]);

out:
	return str - buf;
}
EXPORT_SYMBOL_GPL(tcm_show_caps);

ssize_t tcm_store_cancel(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct tcm_chip *chip = dev_get_drvdata(dev);

	if (chip == NULL)
		return 0;

	chip->vendor.cancel(chip);
	return count;
}
EXPORT_SYMBOL_GPL(tcm_store_cancel);

/*
 * Device file system interface to the TCM
 * when App call file open in usr space ,this func will respone
 */
int tcm_open(struct inode *inode, struct file *file)
{
	int rc = 0, minor = iminor(inode);
	struct tcm_chip *chip = NULL, *pos = NULL;

	spin_lock(&driver_lock);

	list_for_each_entry(pos, &tcm_chip_list, list) {
		if (pos->vendor.miscdev.minor == minor) {
			chip = pos;
			break;
		}
	}

	if (chip == NULL) {
		rc = -ENODEV;
		goto err_out;
	}

	if (chip->num_opens) {
		dev_dbg(chip->dev, "Another process owns this TCM\n");
		rc = -EBUSY;
		goto err_out;
	}

	chip->num_opens++;
	get_device(chip->dev);

	spin_unlock(&driver_lock);

	chip->data_buffer = kmalloc(TCM_BUFSIZE * sizeof(u8), GFP_KERNEL);
	if (chip->data_buffer == NULL) {
		chip->num_opens--;
		put_device(chip->dev);
		return -ENOMEM;
	}

	atomic_set(&chip->data_pending, 0);

	file->private_data = chip;
	return 0;

err_out:
	spin_unlock(&driver_lock);
	return rc;
}
EXPORT_SYMBOL_GPL(tcm_open);

int tcm_release(struct inode *inode, struct file *file)
{
	struct tcm_chip *chip = file->private_data;

	spin_lock(&driver_lock);
	file->private_data = NULL;
	chip->num_opens--;
	del_singleshot_timer_sync(&chip->user_read_timer);
	flush_work(&chip->work);
	atomic_set(&chip->data_pending, 0);
	put_device(chip->dev);
	kfree(chip->data_buffer);
	spin_unlock(&driver_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(tcm_release);

ssize_t tcm_write(struct file *file, const char __user *buf,
		  size_t size, loff_t *off)
{
	struct tcm_chip *chip = file->private_data;
	int in_size = size, out_size;

	/*
	 * cannot perform a write until the read has cleared
	 * either via tcm_read or a user_read_timer timeout
	 */
	while (atomic_read(&chip->data_pending) != 0)
		msleep(TCM_TIMEOUT);

	mutex_lock(&chip->buffer_mutex);

	if (in_size > TCM_BUFSIZE)
		in_size = TCM_BUFSIZE;

	if (copy_from_user(chip->data_buffer, (void __user *)buf, in_size)) {
		mutex_unlock(&chip->buffer_mutex);
		return -EFAULT;
	}

	/* atomic tcm command send and result receive */
	out_size = tcm_transmit(chip, chip->data_buffer, TCM_BUFSIZE);

	if (out_size >= 0) {
		atomic_set(&chip->data_pending, out_size);
		mutex_unlock(&chip->buffer_mutex);

		/* Set a timeout by which the reader must come claim the result */
		mod_timer(&chip->user_read_timer, jiffies + (60 * HZ));
	} else
		mutex_unlock(&chip->buffer_mutex);

	return in_size;
}
EXPORT_SYMBOL_GPL(tcm_write);

ssize_t tcm_read(struct file *file, char __user *buf,
		 size_t size, loff_t *off)
{
	struct tcm_chip *chip = file->private_data;
	int ret_size = 0;

	del_singleshot_timer_sync(&chip->user_read_timer);
	flush_work(&chip->work);
	ret_size = atomic_read(&chip->data_pending);
	atomic_set(&chip->data_pending, 0);
	if (ret_size > 0) {	/* relay data */
		if (size < ret_size)
			ret_size = size;

		mutex_lock(&chip->buffer_mutex);
		if (copy_to_user(buf, chip->data_buffer, ret_size))
			ret_size = -EFAULT;
		mutex_unlock(&chip->buffer_mutex);
	}

	return ret_size;
}
EXPORT_SYMBOL_GPL(tcm_read);

void tcm_remove_hardware(struct device *dev)
{
	struct tcm_chip *chip = dev_get_drvdata(dev);

	if (chip == NULL) {
		dev_err(dev, "No device data found\n");
		return;
	}

	spin_lock(&driver_lock);
	list_del(&chip->list);
	spin_unlock(&driver_lock);

	dev_set_drvdata(dev, NULL);
	misc_deregister(&chip->vendor.miscdev);
	kfree(chip->vendor.miscdev.name);

	sysfs_remove_group(&dev->kobj, chip->vendor.attr_group);
	/* tcm_bios_log_teardown(chip->bios_dir); */

	clear_bit(chip->dev_num, dev_mask);
	kfree(chip);
	put_device(dev);
}
EXPORT_SYMBOL_GPL(tcm_remove_hardware);

static u8 savestate[] = {
	0, 193,			/* TCM_TAG_RQU_COMMAND */
	0, 0, 0, 10,		/* blob length (in bytes) */
	0, 0, 128, 152		/* TCM_ORD_SaveState */
};

/*
 * We are about to suspend. Save the TCM state
 * so that it can be restored.
 */
int tcm_pm_suspend(struct device *dev, pm_message_t pm_state)
{
	struct tcm_chip *chip = dev_get_drvdata(dev);

	if (chip == NULL)
		return -ENODEV;

	tcm_transmit(chip, savestate, sizeof(savestate));
	return 0;
}
EXPORT_SYMBOL_GPL(tcm_pm_suspend);

int tcm_pm_suspend_p(struct device *dev)
{
	struct tcm_chip *chip = dev_get_drvdata(dev);

	if (chip == NULL)
		return -ENODEV;

	tcm_transmit(chip, savestate, sizeof(savestate));
	return 0;
}
EXPORT_SYMBOL_GPL(tcm_pm_suspend_p);

void tcm_startup(struct tcm_chip *chip)
{
	u8 start_up[] = {
		0, 193,			/* TCM_TAG_RQU_COMMAND */
		0, 0, 0, 12,		/* blob length (in bytes) */
		0, 0, 128, 153,		/* TCM_ORD_SaveState */
		0, 1
	};
	if (chip == NULL)
		return;
	tcm_transmit(chip, start_up, sizeof(start_up));
}
EXPORT_SYMBOL_GPL(tcm_startup);

/*
 * Resume from a power safe. The BIOS already restored
 * the TCM state.
 */
int tcm_pm_resume(struct device *dev)
{
	u8 start_up[] = {
		0, 193,			/* TCM_TAG_RQU_COMMAND */
		0, 0, 0, 12,		/* blob length (in bytes) */
		0, 0, 128, 153,		/* TCM_ORD_SaveState */
		0, 1
	};
	struct tcm_chip *chip = dev_get_drvdata(dev);
	/* dev_info(chip->dev ,"--call tcm_pm_resume\n"); */
	if (chip == NULL)
		return -ENODEV;

	tcm_transmit(chip, start_up, sizeof(start_up));
	return 0;
}
EXPORT_SYMBOL_GPL(tcm_pm_resume);

/*
 * Called from tcm_<specific>.c probe function only for devices
 * the driver has determined it should claim.  Prior to calling
 * this function the specific probe function has called pci_enable_device
 * upon errant exit from this function specific probe function should call
 * pci_disable_device
 */
struct tcm_chip *tcm_register_hardware(struct device *dev,
		const struct tcm_vendor_specific *entry)
{
	int rc;
#define DEVNAME_SIZE 7

	char *devname = NULL;
	struct tcm_chip *chip = NULL;

	/* Driver specific per-device data */
	chip = kzalloc(sizeof(*chip), GFP_KERNEL);
	if (chip == NULL) {
		dev_err(dev, "chip kzalloc err\n");
		return NULL;
	}

	mutex_init(&chip->buffer_mutex);
	mutex_init(&chip->tcm_mutex);
	INIT_LIST_HEAD(&chip->list);

	INIT_WORK(&chip->work, timeout_work);
	timer_setup(&chip->user_read_timer, user_reader_timeout, 0);

	memcpy(&chip->vendor, entry, sizeof(struct tcm_vendor_specific));

	chip->dev_num = find_first_zero_bit(dev_mask, TCM_NUM_DEVICES);

	if (chip->dev_num >= TCM_NUM_DEVICES) {
		dev_err(dev, "No available tcm device numbers\n");
		kfree(chip);
		return NULL;
	} else if (chip->dev_num == 0)
		chip->vendor.miscdev.minor = TCM_MINOR;
	else
		chip->vendor.miscdev.minor = MISC_DYNAMIC_MINOR;

	set_bit(chip->dev_num, dev_mask);

	devname = kmalloc(DEVNAME_SIZE, GFP_KERNEL);
	scnprintf(devname, DEVNAME_SIZE, "%s%d", "tcm", chip->dev_num);
	chip->vendor.miscdev.name = devname;

	/* chip->vendor.miscdev.dev = dev; */

	chip->dev = get_device(dev);

	if (misc_register(&chip->vendor.miscdev)) {
		dev_err(chip->dev,
			"unable to misc_register %s, minor %d\n",
			chip->vendor.miscdev.name,
			chip->vendor.miscdev.minor);
		put_device(dev);
		clear_bit(chip->dev_num, dev_mask);
		kfree(chip);
		kfree(devname);
		return NULL;
	}

	spin_lock(&driver_lock);
	dev_set_drvdata(dev, chip);
	list_add(&chip->list, &tcm_chip_list);
	spin_unlock(&driver_lock);

	rc = sysfs_create_group(&dev->kobj, chip->vendor.attr_group);
	/* chip->bios_dir = tcm_bios_log_setup(devname); */

	return chip;
}
EXPORT_SYMBOL_GPL(tcm_register_hardware);

static int __init tcm_init_module(void)
{
	return 0;
}

static void __exit tcm_exit_module(void)
{
}

module_init(tcm_init_module);
module_exit(tcm_exit_module);

MODULE_AUTHOR("Nationz Technologies Inc.");
MODULE_DESCRIPTION("TCM Driver");
MODULE_VERSION("1.1.1.0");
MODULE_LICENSE("GPL");
