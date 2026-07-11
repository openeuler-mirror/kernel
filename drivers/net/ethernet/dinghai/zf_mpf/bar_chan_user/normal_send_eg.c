// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BAR_CHAN_PLOAD_SIZE (2036)
#define BAR_REPS_HDR_LEN (4)
#define DEVICE_FILE "/dev/bar_ioctl_dev"
#define BAR_IOCTL_CMD_NORMAL _IOW('a', 1, struct normal_msg_entity)
struct zxdh_ioctl_send_in {
	u16 pload_len;
	u16 src;
	u16 dst;
	u16 event_id;
};

struct zxdh_ioctl_send_out {
	int ioctl_state;
	int bar_state;
};

struct zxdh_ioctl_recv_in {
	u16 event_id;
	u16 rsv1;
	u32 rsv2;
};

struct zxdh_ioctl_recv_out {
	u16 msg_len;
	u16 rsv1;
	u32 rsv2;
};

struct normal_msg_entity {
	union ioctl_ctrl_hdr {
		struct zxdh_ioctl_send_in send_hdr_in;
		struct zxdh_ioctl_send_out send_hdr_out;
	} hdr;
	u8 pload[BAR_CHAN_PLOAD_SIZE];
};

enum BAR_DRIVER_TYPE {
	MSG_CHAN_END_MPF = 0,
	MSG_CHAN_END_PF,
	MSG_CHAN_END_VF,
	MSG_CHAN_END_RISC,
	MSG_CHAN_END_ERR,
};

int main(void)
{
	int fd, ret;
	struct normal_msg_entity entity = { 0 };
	u8 data[5] = { 0x12, 0x34, 0x53, 0x32, 0xaa };

	entity.hdr.send_hdr_in.pload_len = sizeof(data);
	entity.hdr.send_hdr_in.src = MSG_CHAN_END_PF;
	entity.hdr.send_hdr_in.dst = MSG_CHAN_END_RISC;
	entity.hdr.send_hdr_in.event_id = 5;

	memcpy(entity.pload, data, sizeof(data));

	fd = open(DEVICE_FILE, O_RDWR);
	if (fd < 0) {
		perror("Failed to open the device.");
		return 1;
	}
	printf("reps: 0x%llx.\n", *(u64 *)entity.pload);

	ret = ioctl(fd, BAR_IOCTL_CMD_NORMAL, &entity);
	if (ret < 0) {
		perror("IOCTL command failed.");
		ret = 1;
		goto out;
	}

	if (entity.hdr.send_hdr_out.ioctl_state != 0) {
		printf("ioctl failed, state: %d\n", entity.hdr.send_hdr_out.ioctl_state);
		ret = -1;
		goto out;
	}

	if (entity.hdr.send_hdr_out.bar_state != 0) {
		printf("bar send err, state: %d\n", entity.hdr.send_hdr_out.bar_state);
		ret = entity.hdr.send_hdr_out.bar_state;
		goto out;
	}

	printf("the sum 2byes of data is 0x%x.\n", *(u16 *)entity.pload);

out:
	close(fd);
	return 0;
}
