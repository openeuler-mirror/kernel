/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_IOCTL_H_
#define __YS_IOCTL_H_

#define YSIOCTL_TYPE 'x'

#ifndef BAR_MAX
#define BAR_MAX 6
#endif

#define YS_IOCTL_OP_READ 0
#define YS_IOCTL_OP_WRITE 1

struct ysioctl_info {
	size_t tx_buffer_size; /* output */
	size_t filters_size; /* output */
	int if_index[4]; /* output */
};

struct ysioctl_rw_reg_arg {
	int op; /* 0: read, 1: write */
	unsigned long bar; /* BAR number */
	unsigned long reg; /* register address */
	unsigned long val; /* value to write */
};

struct ysioctl_i2c_arg {
	int op; /* 0: read, 1: write */
	u8 i2c_num;
	u8 regaddr;
	u8 *buffer;
	size_t size;
};

enum {
	YS_IOCTL_MMAP_FLAG_LDMA = 0,
	YS_IOCTL_MMAP_FLAG_BAR = 1,
};

#define YS_IOCR_GET_BAR_SIZE _IOR(YSIOCTL_TYPE, 0xa1, unsigned long[BAR_MAX])
#define YS_IOCX_RW_REG _IOWR(YSIOCTL_TYPE, 0xa2, struct ysioctl_rw_reg_arg)
#define YS_IOCX_RW_I2C _IOWR(YSIOCTL_TYPE, 0xa3, struct ysioctl_i2c_arg)
#define YS_IOCW_SET_MMAP_FLAG _IOW(YSIOCTL_TYPE, 0xa4, u32)

#endif /* __YS_IOCTL_H_ */
