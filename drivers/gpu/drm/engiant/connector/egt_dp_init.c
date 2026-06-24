// SPDX-License-Identifier: GPL-2.0
/*
 * DisplayPort Driver Init functions
 *
 * Copyright (c) 2019-2026, New H3C Semiconductor Technologies Co., Ltd.
 */

#include <drm/drm_edid.h>
#include <drm/drm_probe_helper.h>
#include <linux/pci.h>
#include "vs_dc.h"
#include "vs_gem.h"
#include "egt_dp_phy.h"
#include "egt_dp.h"


const struct drm_connector_helper_funcs egt_dp_connector_helper_funcs = {
	.get_modes				= egt_dp_get_modes,
	.best_encoder			= egt_dp_best_encoder,
	.mode_valid				= egt_dp_mode_valid,
};

const struct drm_connector_funcs egt_dp_connector_funcs = {
	.detect					= egt_dp_connected_detect,
	.destroy				= egt_dp_destroy,
	.atomic_set_property	= egt_dp_atomic_set_property,
	.atomic_get_property	= egt_dp_atomic_get_property,
	.atomic_duplicate_state	= drm_atomic_helper_connector_duplicate_state,
	.atomic_destroy_state	= drm_atomic_helper_connector_destroy_state,
	.fill_modes				= drm_helper_probe_single_connector_modes,
	.reset					= drm_atomic_helper_connector_reset,
};

const struct drm_encoder_helper_funcs egt_dp_encoder_helper_funcs = {
	.disable			= egt_dp_dis_encoder,
	.enable				= egt_dp_en_encoder,
	.atomic_mode_set	= egt_dp_atomic_mode_set,
	.atomic_check		= egt_dp_atomic_check,
};

const struct drm_encoder_funcs egt_dp_encoder_funcs = {
	.destroy = drm_encoder_cleanup,
};

static irqreturn_t egt_dp_irq_handle(__maybe_unused int irq, void *data)
{
	struct egt_displayport *dp = data;
	u32 pci_intr_sts = 0;
	u32 intr_sts = 0;

	pci_intr_sts = readl(dp->mem_base.pci_base + EGT_PCI_INTRREG_OFFSET);

	if (pci_intr_sts == 0xffffffff || !(pci_intr_sts & 0x40000))
		return IRQ_NONE;

	writel(0x40000, dp->mem_base.pci_base + EGT_PCI_INTRREG_OFFSET);

	/* clear irq */
	intr_sts = egt_dp_read(DP_SOURCE_TX_STATUS, dp);
	pr_debug("dp tx intr sts = %#x\n", intr_sts);
	if (!intr_sts)
		return IRQ_NONE;

	egt_dp_write(0x0, DP_SOURCE_TX_STATUS, dp);

	/* adjust status and work */
	if ((intr_sts & EGT_TX_LOGIC_MASK) == 0)
		dp->connected = 0;

	if ((intr_sts & EGT_TX_LOGIC_MASK)) {
		dev_dbg_ratelimited(dp->dev, "dp tx hpd event\n");
		schedule_delayed_work(&dp->hot_plug_detect, msecs_to_jiffies(100));
	} else {
		return IRQ_NONE;
	}

	return IRQ_HANDLED;
}

static int egt_dp_aux_wait_reply(struct egt_displayport *dp)
{
	u32 start_time = 0;
	u32 current_time = 0;
	u32 reg = 0;
	u32 reg1 = 0;
	u32 timeout_flag = 0;
	u32 time = 0;
	s64 elapsed_us = 0;
	unsigned int timeout_us = 100000;
	ktime_t ktime_start = 0;

	start_time = egt_dp_read(DP_SOURCE_TIMESTAMP, dp);
	ktime_start = ktime_get();
	time = EGT_DP_AUX_STD_TOUT / 100 * EGT_TX_100US_TICKS;

	while (1) {
		reg = egt_dp_read(DP_SOURCE_AUX_CONTROL, dp);
		current_time = egt_dp_read(DP_SOURCE_TIMESTAMP, dp);

		if (((current_time - start_time) & EGT_TX_TIME_MASK) >= time)
			timeout_flag = 1;

		reg1 = egt_dp_read(DP_SOURCE_AUX_CONTROL, dp);
		if ((reg | reg1) & EGT_TX_AUXDONE_MASK)
			return 0;

		if (timeout_flag) {
			pr_warn("AUX reply timeout\n");
			egt_dp_write(0x01, DP_SOURCE_AUX_RESET, dp);
			egt_dp_ticks_wait_us(400, dp);
			egt_dp_write(0x00, DP_SOURCE_AUX_RESET, dp);
			return -ETIMEDOUT;
		}

		elapsed_us = ktime_to_us(ktime_sub(ktime_get(), ktime_start));
		if (elapsed_us > timeout_us) {
			pr_warn("AUX reply timeout, elapsed=%lld us\n", (long long)elapsed_us);
			return -ETIMEDOUT;
		}
	}

}

static int egt_dp_aux_wait_ok(struct egt_displayport *dp)
{
	unsigned int start_time = 0;
	unsigned int count = 0;
	u32 timeout_flag = 0;
	u32 current_ts = 0;
	u32 time = 0;
	s64 elapsed_us = 0;
	unsigned int timeout_us = 100000;
	ktime_t ktime_start = 0;

	start_time = egt_dp_read(DP_SOURCE_TIMESTAMP, dp);
	ktime_start = ktime_get();
	time = 400 / 100 * EGT_TX_100US_TICKS;

	while (!(egt_dp_read(DP_SOURCE_AUX_CONTROL, dp) & EGT_TX_AUXREADY_MASK)) {
		current_ts = egt_dp_read(DP_SOURCE_TIMESTAMP, dp);
		if (((current_ts - start_time) & EGT_TX_TIME_MASK) >= time)
			timeout_flag = 1;

		if (timeout_flag) {
			pr_warn("AUX busy\n");
			count++;
			egt_dp_write(0x01, DP_SOURCE_AUX_RESET, dp);
			egt_dp_ticks_wait_us(400, dp);
			egt_dp_write(0x00, DP_SOURCE_AUX_RESET, dp);
			start_time = egt_dp_read(DP_SOURCE_TIMESTAMP, dp);
		}
		if (count > 6) {
			pr_warn("AUX wait timeout over 6\n");
			return -ETIMEDOUT;
		}

		elapsed_us = ktime_to_us(ktime_sub(ktime_get(), ktime_start));
		if (elapsed_us > timeout_us) {
			pr_warn("wait AUX timeout, elapsed=%lld us\n", (long long)elapsed_us);
			return -ETIMEDOUT;
		}
	}

	return 0;
}

static void egt_dp_set_aux(struct egt_displayport *dp, u32 op, u32 addr, u8 bytes)
{
	egt_dp_write(op, DP_SOURCE_AUX_COMMAND, dp);
	egt_dp_write((addr) >> 8, DP_SOURCE_AUX_BYTE0, dp);
	egt_dp_write(addr, DP_SOURCE_AUX_BYTE1, dp);
	egt_dp_write(bytes - 1, DP_SOURCE_AUX_BYTE2, dp);
}

static int egt_dp_check_aux_native(struct egt_displayport *dp, struct drm_dp_aux_msg *msg)
{
	bool is_read = (msg->request & EGT_DP_AUX_RD_BIT) ? true : false;
	unsigned int aux_256b = dp->aux_256b_capab;
	unsigned int count = 0;
	u8 *reply = &msg->reply;
	u8 *buffer = msg->buffer;
	u32 reg = 0;
	u32 i = 0;
	u32 len = 0;
	u32 ret = 0;

	if (is_read) {
		len = (egt_dp_read(DP_SOURCE_AUX_CONTROL, dp) & 0x1FF) - 1;
		if (len != msg->size)
			return RET_OUT;
	}

	reg = egt_dp_read(DP_SOURCE_AUX_COMMAND, dp);
	if (reply)
		*reply = (reg >> 4) & DP_AUX_NATIVE_REPLY_MASK;

	switch (reg & 0xF0) {
	case EGT_DP_AUX_ACK:
		if (is_read) {
			if (aux_256b) {
				for (i = 0; i < len; i++) {
					egt_dp_write(i << 16, DP_SOURCE_AUX_PAYLOAD, dp);
					buffer[i] = egt_dp_read(DP_SOURCE_AUX_PAYLOAD, dp) & 0xFF;
				}
			} else {
				for (i = 0; i < len; i++)
					buffer[i] = egt_dp_read(DP_SOURCE_AUX_BYTE0 + i * 4, dp);
			}
		}
		break;
	case EGT_DP_AUX_NACK:
		pr_debug("rx EGT_DP_AUX_NACK\n");
		break;
	case EGT_DP_AUX_DEFER:
		count++;
		if (count < EGT_DP_AUX_RETRY_TIMES)
			return RET_RETRY;
		pr_debug("rx EGT_DP_AUX_DEFER over times\n");
		break;
	default:
		pr_debug("rx reply invalid\n");
		break;
	}

	return ret;
}

static int egt_dp_aux_before(struct egt_displayport *dp, u8 size, int *irq_en, int *aux_256b)
{
	u8 val = 0;
	int ret = 0;

	val = (egt_dp_read(DP_SOURCE_TX_CONTROL, dp) >> 31) & 0x01;
	if (val) {
		if (irq_en) {
			*irq_en = 1;
			egt_dp_set_hpd_irq(dp, 0);
		}
	}

	if (!aux_256b)
		return -EIO;

	*aux_256b = dp->aux_256b_capab;
	if ((*aux_256b == 0) && (size > 16))
		return -EIO;

	return ret;
}

static int egt_dp_aux_native_transfer(struct egt_displayport *dp, struct drm_dp_aux_msg *msg)
{
	bool is_read = (msg->request & EGT_DP_AUX_RD_BIT) ? true : false;
	u8 *buffer = msg->buffer;
	u32 op = (msg->request & EGT_DP_AUX_RD_BIT) ? EGT_DP_AUX_NATIVE_RD : EGT_DP_AUX_NATIVE_WR;
	u32 i = 0;
	u32 length = 0;
	int ret = 0;
	int irq_en = 0;
	int aux_256b = 0;
	int cntr = 0;
	unsigned int got_reply = 0;
	unsigned int mode = 0;

	ret = egt_dp_aux_before(dp, msg->size, &irq_en, &aux_256b);
	if (ret < 0)
		goto out;

	mode = egt_dp_read(DP_SOURCE_AUX_CONTROL, dp) & 0x600;

retry:
	got_reply = 0;
	cntr = 0;

	while (!got_reply) {
		if (egt_dp_aux_wait_ok(dp)) {
			pr_err("AUX busy\n");
			ret = -EBUSY;
			goto out;
		}

		op |= ((msg->address >> 16) & 0x0F);
		egt_dp_set_aux(dp, op, msg->address, msg->size);

		if (!is_read) {
			if (aux_256b) {
				for (i = 0; i < msg->size; i++)
					egt_dp_write((i << 16) | (1 << 8) | buffer[i],
								 DP_SOURCE_AUX_PAYLOAD, dp);
			} else {
				for (i = 0; i < msg->size; i++)
					egt_dp_write(buffer[i], DP_SOURCE_AUX_BYTE3 + i * 4, dp);
			}

			length = 0x4 + msg->size;
		} else {
			length = 0x4;
		}

		egt_dp_write(mode | length, DP_SOURCE_AUX_CONTROL, dp);

		if (egt_dp_aux_wait_reply(dp))
			pr_warn("rx reply timeout\n");
		else
			got_reply = 1;

		cntr++;
		if (cntr >= 5)
			break;
	}

	if (!got_reply) {
		ret = -ETIMEDOUT;
		goto out;
	}

	/* check AUX ack */
	ret = egt_dp_check_aux_native(dp, msg);
	if (ret == RET_OUT) {
		ret = -EIO;
		goto out;
	}
	if (ret == RET_RETRY)
		goto retry;

out:
	if (irq_en == 1)
		egt_dp_set_hpd_irq(dp, 1);

	return ret;
}

static int egt_dp_aux_i2c_update(struct egt_displayport *dp, u8 mot, u32 edp_alp_mode,
					u8 addr, u8 *reply, size_t *len)
{
	unsigned int resend_cntr = 0;
	unsigned int got_reply = 0;
	int ret = 0;
	int length = 0;
	u8 cmd = 0;

	while ((resend_cntr++ < 5) && !got_reply) {
		if (egt_dp_aux_wait_ok(dp)) {
			pr_err("AUX controller busy\n");
			ret = -EBUSY;
			goto exit;
		}

		cmd = mot ? (EGT_DP_AUX_UPDATE_I2C | EGT_DP_AUX_MOT_I2C) : EGT_DP_AUX_UPDATE_I2C;
		egt_dp_write(cmd, DP_SOURCE_AUX_COMMAND, dp);
		egt_dp_write(0, DP_SOURCE_AUX_BYTE0, dp);
		egt_dp_write(addr, DP_SOURCE_AUX_BYTE1, dp);

		length = 3;
		egt_dp_write(edp_alp_mode | length, DP_SOURCE_AUX_CONTROL, dp);

		if (egt_dp_aux_wait_reply(dp))
			pr_warn("sink reply timeout\n");
		else
			got_reply = 1;
	}

	if (!got_reply) {
		ret = -ETIMEDOUT;
		goto exit;
	}

	*len = (egt_dp_read(DP_SOURCE_AUX_CONTROL, dp) & 0x1FF) - 1;
	*reply = egt_dp_read(DP_SOURCE_AUX_COMMAND, dp) & 0xF0;

exit:
	return ret;
}

static int egt_dp_aux_i2c_inner_transfer(struct egt_displayport *dp, bool is_read,
				u32 op, u8 aux_256b, u8 address, size_t size,
				u8 *data, u8 *reply, size_t *len)
{
	unsigned int cnt = 0;
	unsigned int got_reply = 0;
	int ret = 0;
	int length = 0;
	int i = 0;

	got_reply = 0;
	cnt = 0;
	while (!got_reply) {
		if (egt_dp_aux_wait_ok(dp)) {
			pr_err("AUX controller busy\n");
			ret = -EBUSY;
			goto out;
		}

		egt_dp_write(op, DP_SOURCE_AUX_COMMAND, dp);
		egt_dp_write(0, DP_SOURCE_AUX_BYTE0, dp);
		egt_dp_write(address, DP_SOURCE_AUX_BYTE1, dp);
		egt_dp_write(size - 1, DP_SOURCE_AUX_BYTE2, dp);

		if (is_read) {
			if (size == 0)
				length = 3;
			else
				length = 4;
		} else {
			if (aux_256b) {
				for (i = 0; i < size; i++)
					egt_dp_write((i << 16) | (1 << 8) | data[i],
								 DP_SOURCE_AUX_PAYLOAD, dp);
			} else {
				for (i = 0; i < size; i++)
					egt_dp_write(data[i], DP_SOURCE_AUX_BYTE3 + i * 4, dp);
			}

			if (size == 0)
				length = 3;
			else
				length = 4 + size;
		}

		egt_dp_write((0x0 | length), DP_SOURCE_AUX_CONTROL, dp);

		if (egt_dp_aux_wait_reply(dp))
			pr_warn("rx reply timeout\n");
		else
			got_reply = 1;

		cnt++;
		if (cnt >= 5)
			break;

	}

	if (!got_reply) {
		ret = -ETIMEDOUT;
		goto out;
	}

	*len = (egt_dp_read(DP_SOURCE_AUX_CONTROL, dp) & 0x1FF) - 1;
	*reply = egt_dp_read(DP_SOURCE_AUX_COMMAND, dp) & 0xF0;

out:
	return ret;
}

static void egt_dp_check_aux_i2c_ack(struct egt_displayport *dp, u8 *buffer,
						size_t bytes, unsigned int aux_256b,
						struct drm_dp_aux_msg *msg, size_t size)
{
	int i = 0;
	u8 data = 0;

	if (aux_256b) {
		for (i = 0; i < bytes; i++) {
			egt_dp_write(i << 16, DP_SOURCE_AUX_PAYLOAD, dp);
			data = (u8) (egt_dp_read(DP_SOURCE_AUX_PAYLOAD, dp) & 0xFF);
			buffer[msg->size - size + i] = data;
		}
	} else {
		for (i = 0; i < bytes; i++) {
			data = (u8) (egt_dp_read(DP_SOURCE_AUX_BYTE0 + i * 4, dp) & 0xFF);
			buffer[msg->size - size + i] = data;
		}
	}
}

static int egt_dp_check_aux_i2c(struct egt_displayport *dp, struct drm_dp_aux_msg *msg)
{
	bool is_read = (msg->request & EGT_DP_AUX_READ_BIT) ? true : false;
	u8 *reply = &msg->reply;
	u8 *buffer = msg->buffer;
	u8 reply_reg = 0;
	u8 val = 0;
	u8 val_i2c = 0;
	u32 op = 0;
	u32 op_r = 0;
	u32 op_w = 0;
	size_t size = msg->size;
	size_t bytes = 0;
	int mot = (msg->request & DP_AUX_I2C_MOT) ? 1 : 0;
	int bytes_written = 0;
	int count = 0;
	int ret = 0;
	int status = 0;
	unsigned int aux_256b = dp->aux_256b_capab;

	op_r = mot ? (EGT_DP_AUX_RD_I2C | EGT_DP_AUX_MOT_I2C) : EGT_DP_AUX_RD_I2C;
	op_w = mot ? (EGT_DP_AUX_WR_I2C | EGT_DP_AUX_MOT_I2C) : EGT_DP_AUX_WR_I2C;
	op = (msg->request & EGT_DP_AUX_READ_BIT) ? op_r : op_w;

	do {
		ret = egt_dp_aux_i2c_inner_transfer(dp, is_read, op, aux_256b, msg->address, size,
					(is_read ? NULL : msg->buffer + msg->size - size),
					&reply_reg, &bytes);
		if (reply)
			*reply = (reply_reg >> 4) & DP_AUX_I2C_REPLY_MASK;

check_reply:
		if (!is_read) {
			if (aux_256b) {
				egt_dp_write(0 << 16, DP_SOURCE_AUX_PAYLOAD, dp);
				bytes_written = (egt_dp_read(DP_SOURCE_AUX_PAYLOAD, dp) & 0xFF);
			} else {
				bytes_written = (egt_dp_read(DP_SOURCE_AUX_BYTE0, dp) & 0x1F);
			}
		}

		val = reply_reg & 0x30;
		val_i2c = reply_reg & 0xC0;
		switch (val) {
		case EGT_DP_AUX_ACK:
			switch (val_i2c) {
			case EGT_DP_AUX_ACK_I2C:
				if (is_read) {
					egt_dp_check_aux_i2c_ack(dp, buffer, bytes,
								aux_256b, msg, size);
					size -= bytes;
					count++;
				}
				if (!is_read) {
					if (bytes) {
						size -= bytes_written;
						count++;
					} else {
						return ret;
					}
				}
				break;
			case EGT_DP_AUX_NACK_I2C:
				if (!is_read) {
					if (bytes) {
						size -= bytes_written;
						count++;
					} else {
						pr_warn("rx replied I2C_NACK\n");
						return -ETIMEDOUT;
					}
				} else {
					pr_warn("rx replied I2C_NACK\n");
					return -ETIMEDOUT;
				}
				break;
			case EGT_DP_AUX_DEFER_I2C:
				if (!is_read) {
					if (count++ >= 16)
						break;
					status = egt_dp_aux_i2c_update(dp,
						((msg->request & DP_AUX_I2C_MOT) ? 1 : 0),
						0, msg->address, &reply_reg, &bytes);
					if (status)
						return -ETIMEDOUT;

					goto check_reply;
				} else {
					pr_err("can not be here\n");
					return -EIO;
				}
				break;
			default:
				break;
			}
			break;
		case EGT_DP_AUX_DEFER:
			count++;
			pr_debug("rx replied EGT_DP_AUX_DEFER\n");
			break;
		case EGT_DP_AUX_NACK:
			pr_debug("rx replied EGT_DP_AUX_NACK\n");
			fallthrough;
		default:
			pr_warn("rx replied invalid\n");
			return -EIO;
		}
	} while ((size > 0) && (count < EGT_DP_AUX_RETRY_TIMES));

	if (size > 0)
		ret = -EIO;

	if (count >= EGT_DP_AUX_RETRY_TIMES)
		ret = -ETIMEDOUT;

	return ret;
}

static int egt_dp_aux_i2c_transfer(struct egt_displayport *dp, struct drm_dp_aux_msg *msg)
{
	int irq_en = 0;
	int aux_256b = 0;
	int ret = 0;

	ret = egt_dp_aux_before(dp, msg->size, &irq_en, &aux_256b);
	if (ret < 0)
		goto out;

	/* check and deal with i2c-over-aux reply */
	ret = egt_dp_check_aux_i2c(dp, msg);

out:
	if (irq_en == 1)
		egt_dp_set_hpd_irq(dp, 1);

	return ret;
}

static ssize_t egt_dp_aux_transfer(struct drm_dp_aux *aux, struct drm_dp_aux_msg *msg)
{
	struct egt_displayport *dp = container_of(aux, struct egt_displayport, aux);
	int i = 0;
	int times = 4;
	int ret = 0;

	for (i = 0; i < times; i++) {
		switch (msg->request & ~DP_AUX_I2C_MOT) {
		case DP_AUX_I2C_WRITE:
		case DP_AUX_I2C_WRITE_STATUS_UPDATE:
		case DP_AUX_I2C_READ:
			ret = egt_dp_aux_i2c_transfer(dp, msg);
			if (!ret)
				return msg->size;
			break;
		case DP_AUX_NATIVE_WRITE:
		case DP_AUX_NATIVE_READ:
			ret = egt_dp_aux_native_transfer(dp, msg);
			if (!ret)
				return msg->size;
			break;
		default:
			return -EINVAL;
		}

		usleep_range(390, 500);
	}

	if (ret < 0)
		pr_warn("AUX transfer msg = %d, count = %d\n", (msg->request & ~DP_AUX_I2C_MOT), i);

	return ret;
}

static int egt_dp_aux_init(struct egt_displayport *dp)
{
	int ret = 0;

	egt_dp_write(0x01, DP_SOURCE_AUX_RESET, dp);
	egt_dp_ticks_wait_us(400, dp);
	egt_dp_write(0x00, DP_SOURCE_AUX_RESET, dp);

	dp->aux.name = "Egt DP AUX";
	dp->aux.dev = dp->dev;
	dp->aux.drm_dev = dp->drm;
	dp->aux.transfer = egt_dp_aux_transfer;
	ret = drm_dp_aux_register(&dp->aux);

	return ret;
}

static void egt_dp_init_capab(struct egt_displayport *dp)
{
	u32 val = 0;

	val = egt_dp_read(DP_SOURCE_TX_CAPAB, dp);
	dp->aux_256b_capab = ((val >> 21) & 1);
	dp->max_lanes = 1;
	dp->max_link_rate = drm_dp_bw_code_to_link_rate(0x14);

	pr_debug("tx capab aux_256b_capab = %d, max_lanes = %d, max_linkrate = %d\n",
				 dp->aux_256b_capab, dp->max_lanes, dp->max_link_rate);
}

static struct egt_displayport *egt_dp_init(struct drm_device *drm_dev)
{
	struct vs_drm_private *priv = drm_dev->dev_private;
	struct pci_dev *pdev = NULL;
	struct device *dev = NULL;
	struct egt_displayport *dp = NULL;
	u32 val = 0;

	pdev = to_pci_dev(drm_dev->dev);
	dev = &pdev->dev;

	dp = devm_kzalloc(dev, sizeof(*dp), GFP_KERNEL);
	if (dp == NULL)
		return NULL;

	pr_debug("irq_num[2] | dp_base | irq_num[4] | mbox_base | phy_base | pcie_intr_base\n");
	pr_debug("  %#x  |  %p  |  %#x  |  %d  |  %p  |  %p\n", priv->irq_num[2], priv->dp_base,
			priv->irq_num[4], dp->mem_base.mbox_iobase,
			priv->dp_phy_base, priv->pci_base);

	dp->mem_base.dp_base = priv->dp_base;
	dp->irq =  priv->irq_num[2];
	dp->mem_base.pci_mbox_base = priv->mbox_base;
	dp->mem_base.mbox_iobase = EGT_DP_SIO_IO_CH1;
	dp->mem_base.pci_base = priv->pci_base;

	dp->dev = dev;
	dp->connector_sts = connector_status_disconnected;

	dp->mem_base.dp_phy0_base = priv->dp_phy0_base;
	dp->mem_base.dp_phy1_base = priv->dp_phy1_base;
	dp->mem_base.pixel_pll_base = priv->crg_base;
	dp->mem_base.crg_base = priv->crg_hsio_base;

	egt_dp_init_capab(dp);

	egt_dp_set_bits_per_pixel(dp, DRM_FORMAT_RGB888);

	egt_dp_write(0x02, DP_SOURCE_PWR_MNG, dp);

	val = egt_dp_read(DP_SOURCE_TX_CONTROL, dp);
	val &= ~(1 << 10);
	val |= (1 << 10);
	egt_dp_write(val, DP_SOURCE_TX_CONTROL, dp);

	mutex_init(&dp->lock);

	return dp;
}

static int egt_dp_driver_init(struct drm_device *drm_dev,
					struct egt_displayport *dp, u32 crtc_mask)
{
	struct drm_connector *connector = NULL;
	struct drm_encoder *encoder = NULL;
	int ret = 0;

	connector = &dp->connector;
	encoder = &dp->encoder;

	drm_encoder_helper_add(encoder, &egt_dp_encoder_helper_funcs);
	encoder->possible_crtcs = crtc_mask;

	connector->polled = DRM_CONNECTOR_POLL_HPD;
	ret = drm_connector_init(drm_dev, connector, &egt_dp_connector_funcs,
							 DRM_MODE_CONNECTOR_DisplayPort);
	if (ret)
		return ret;

	/* Init drm_connector_helper */
	drm_connector_helper_add(connector, &egt_dp_connector_helper_funcs);
	connector->interlace_allowed = false;
	connector->doublescan_allowed = false;
	connector->dpms = DRM_MODE_DPMS_OFF;

	return ret;
}

int egt_dp_device_init(struct drm_device *drm_dev)
{
	struct pci_dev *pdev = NULL;
	struct device *dev = NULL;
	struct egt_displayport *dp = NULL;
	struct drm_crtc *crtc = NULL;
	struct vs_dc *dc = NULL;
	u8 target_bpc = 8;
	u32 crtc_mask = 0;
	int ret = 0;

	if (!drm_dev) {
		pr_err("init drm_dev is NULL\n");
		return -EIO;
	}

	pdev = to_pci_dev(drm_dev->dev);
	dev = &pdev->dev;
	dc = dev_get_drvdata(dev);

	dp = egt_dp_init(drm_dev);
	if (!dp)
		return -ENOMEM;

	dc->dp = dp;

	drm_for_each_crtc(crtc, drm_dev)
		crtc_mask |= drm_crtc_mask(crtc);

	dp->drm = drm_dev;
	ret = drm_encoder_init(drm_dev, &dp->encoder, &egt_dp_encoder_funcs,
							DRM_MODE_ENCODER_DPMST, NULL);
	if (ret)
		return -EIO;

	ret = egt_dp_driver_init(drm_dev, dp, crtc_mask);
	if (ret) {
		pr_err("init connctor with drm failed!\n");
		goto encoder_cleanup;
	}

	ret = drm_connector_register(&dp->connector);
	if (ret)
		goto connector_cleanup;

	ret = drm_connector_attach_encoder(&dp->connector, &dp->encoder);
	if (ret) {
		pr_err("failed to attach connector and encoder!\n");
		goto connector_unregister;
	}

	if (dp->connector.display_info.bpc > 0)
		target_bpc = dp->connector.display_info.bpc;

	dp->tx_cfg.bpc = target_bpc;
	dp->tx_cfg.bpp = dp->tx_cfg.bpc * dp->tx_cfg.num_colors;

	ret = egt_dp_aux_init(dp);
	if (ret < 0) {
		pr_err("init DP aux failed\n");
		goto connector_unregister;
	}

	INIT_DELAYED_WORK(&dp->hot_plug_detect, egt_dptx_hpd_work);
	ret = request_irq(dp->irq, egt_dp_irq_handle, IRQF_SHARED, dev_name(dp->dev), dp);
	if (ret < 0) {
		pr_err("request display port irq failed\n");
		goto aux_unregister;
	}

	/* send vdp stop msg */
	egt_dp_msg_send(dp, EGT_DC_TIMING_STOP);

	egt_dp_set_hpd_irq(dp, 1);

	schedule_delayed_work(&dp->hot_plug_detect, 100);

	return 0;

aux_unregister:
	drm_dp_aux_unregister(&dp->aux);
connector_unregister:
	drm_connector_unregister(&dp->connector);
connector_cleanup:
	drm_connector_cleanup(&dp->connector);
encoder_cleanup:
	drm_encoder_cleanup(&dp->encoder);

	return ret;
}

void egt_dp_device_deinit(struct drm_device *drm_dev)
{
	struct pci_dev *pdev = NULL;
	struct device *dev = NULL;
	struct vs_dc *dc = NULL;
	struct egt_displayport *dp = NULL;
	u32 mbox_data[4] = { 0 };

	pdev = to_pci_dev(drm_dev->dev);
	dev = &pdev->dev;

	dc = dev_get_drvdata(dev);
	dp = dc->dp;

	mbox_data[0] = EGT_DC_TIMING_STOP;
	egt_dp_msg_send_enable(dp, mbox_data);

	cancel_delayed_work_sync(&dp->hot_plug_detect);

	free_irq(dp->irq, dp);

	drm_dp_aux_unregister(&dp->aux);
	drm_connector_unregister(&dp->connector);
	drm_connector_cleanup(&dp->connector);
}

MODULE_DESCRIPTION("Engiant DP Initialization Driver");
MODULE_LICENSE("GPL");
