// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <limits.h>
#include <stdint.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <linux/dm-ioctl.h>
#include <linux/fiemap.h>
#include <linux/fs.h>

#include <linux/nds_p2p.h>
#include "p2p_common.h"

#define P2P_SECTOR_SIZE 512U
#define P2P_SECTORS_PER_KB (1024U / P2P_SECTOR_SIZE)
#define P2P_DM_CONTROL "/dev/mapper/control"
#define P2P_DM_BUFFER_SIZE (16U << 10)
#define P2P_UNSUPPORTED_FIEMAP_FLAGS \
	(FIEMAP_EXTENT_UNKNOWN | FIEMAP_EXTENT_DELALLOC | \
	 FIEMAP_EXTENT_ENCODED | FIEMAP_EXTENT_DATA_ENCRYPTED | \
	 FIEMAP_EXTENT_NOT_ALIGNED | FIEMAP_EXTENT_DATA_INLINE | \
	 FIEMAP_EXTENT_DATA_TAIL | FIEMAP_EXTENT_UNWRITTEN)

struct raid0_member {
	int slot;
	struct topo_user_bdev bdev;
};

static int parse_devt(const char *text, dev_t *devt)
{
	unsigned int dev_major;
	unsigned int dev_minor;
	char trailing;

	if (sscanf(text, "%u:%u %c", &dev_major, &dev_minor, &trailing) != 2)
		return -EINVAL;
	*devt = makedev(dev_major, dev_minor);
	return 0;
}

int p2p_open_dev(void)
{
	int dev_fd;
	int err;

	dev_fd = open("/dev/p2p_device", O_RDWR | O_CLOEXEC);
	if (dev_fd < 0) {
		err = -errno;
		fprintf(stderr, "open /dev/p2p_device failed, errno: %d\n", err);
		return err;
	}

	return dev_fd;
}

static int sysfs_path(char *path, size_t size, dev_t devt,
		      const char *suffix)
{
	int len;

	len = snprintf(path, size, "/sys/dev/block/%u:%u/%s",
		       major(devt), minor(devt), suffix);
	if (len < 0)
		return -errno;
	if ((size_t)len >= size)
		return -ENAMETOOLONG;
	return 0;
}

static int path_exists(dev_t devt, const char *suffix)
{
	char path[PATH_MAX];
	struct stat st;
	int err;

	err = sysfs_path(path, sizeof(path), devt, suffix);
	if (err)
		return 0;
	return !stat(path, &st);
}

static int validate_nvme_component(dev_t devt)
{
	if (path_exists(devt, "partition") ||
	    !path_exists(devt, "device/subsysnqn") ||
	    path_exists(devt, "device/iopolicy"))
		return -EOPNOTSUPP;
	return 0;
}

static int read_text_at(int dir_fd, const char *path, char *buf, size_t size)
{
	ssize_t got;
	int fd;
	int err;

	fd = openat(dir_fd, path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	got = read(fd, buf, size - 1);
	if (got < 0) {
		err = -errno;
		close(fd);
		return err;
	}
	if ((size_t)got == size - 1) {
		close(fd);
		return -E2BIG;
	}
	close(fd);
	buf[got] = '\0';
	return 0;
}

static int read_text(const char *path, char *buf, size_t size)
{
	return read_text_at(AT_FDCWD, path, buf, size);
}

static int read_sysfs_text(dev_t devt, const char *suffix, char *buf,
			   size_t size)
{
	char path[PATH_MAX];
	int err;

	err = sysfs_path(path, sizeof(path), devt, suffix);
	if (err)
		return err;
	return read_text(path, buf, size);
}

static int read_sysfs_u64(dev_t devt, const char *suffix,
			  unsigned long long *value)
{
	char buf[64];
	int err;

	err = read_sysfs_text(devt, suffix, buf, sizeof(buf));
	if (err)
		return err;
	*value = strtoull(buf, NULL, 10);
	return 0;
}

static int validate_nvme_component_input(dev_t devt)
{
	char parent_devt[64];
	dev_t whole_dev;
	int err;

	if (!path_exists(devt, "partition"))
		return validate_nvme_component(devt);

	err = read_sysfs_text(devt, "../dev", parent_devt,
			      sizeof(parent_devt));
	if (err)
		return err;
	err = parse_devt(parent_devt, &whole_dev);
	if (err)
		return err;
	return validate_nvme_component(whole_dev);
}

static int get_block_size_sectors(const char *dev, uint64_t *size_sectors)
{
	uint64_t size_bytes;
	int fd;
	int err;

	fd = open(dev, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	if (ioctl(fd, BLKGETSIZE64, &size_bytes) < 0)
		err = -errno;
	else
		err = 0;
	close(fd);
	if (err)
		return err;
	if (!size_bytes || size_bytes % P2P_SECTOR_SIZE) {
		fprintf(stderr, "invalid block-device size %llu for %s\n",
			(unsigned long long)size_bytes, dev);
		return -EINVAL;
	}

	*size_sectors = size_bytes / P2P_SECTOR_SIZE;
	return 0;
}

static int discover_nvme(const char *dev, dev_t top_dev,
			 struct topo_user_cfg *cfg)
{
	uint64_t size_sectors = 0;
	int err;

	err = validate_nvme_component_input(top_dev);
	if (err)
		return err;
	err = get_block_size_sectors(dev, &size_sectors);
	if (err)
		return err;

	memcpy(cfg->name, "nvme", sizeof("nvme"));
	cfg->nr_devs = 1;
	cfg->top_dev = top_dev;
	cfg->bdevs[0].dev_id = top_dev;
	cfg->bdevs[0].reserved = 0;
	cfg->bdevs[0].size_sector = size_sectors;
	cfg->bdevs[0].start_sector = 0;
	return 0;
}

static int parse_linear_params(const char *params, dev_t *devt,
			       unsigned long long *start_sector)
{
	unsigned int dev_major;
	unsigned int dev_minor;
	int consumed = 0;

	if (sscanf(params, "%u:%u %llu %n", &dev_major, &dev_minor,
		   start_sector, &consumed) != 3)
		return -EINVAL;
	while (isspace((unsigned char)params[consumed]))
		consumed++;
	if (params[consumed])
		return -EINVAL;

	*devt = makedev(dev_major, dev_minor);
	return validate_nvme_component_input(*devt);
}

static int dm_table_query(dev_t top_dev, void **buffer_out)
{
	struct dm_ioctl *dmi;
	void *buffer;
	int control_fd;
	int err;

	control_fd = open(P2P_DM_CONTROL, O_RDWR | O_CLOEXEC);
	if (control_fd < 0) {
		err = -errno;
		fprintf(stderr, "open %s failed, errno: %d\n",
			P2P_DM_CONTROL, err);
		return err;
	}

	buffer = calloc(1, P2P_DM_BUFFER_SIZE);
	if (!buffer) {
		err = -ENOMEM;
		fprintf(stderr, "allocate device-mapper table buffer failed: %d\n",
			err);
		goto out;
	}
	dmi = buffer;
	dmi->version[0] = 4;
	/* DM_TABLE_STATUS has existed since interface version 4.0. */
	dmi->version[1] = 0;
	dmi->version[2] = 0;
	dmi->data_size = P2P_DM_BUFFER_SIZE;
	dmi->data_start = sizeof(*dmi);
	dmi->flags = DM_STATUS_TABLE_FLAG;
	dmi->dev = top_dev;

	if (ioctl(control_fd, DM_TABLE_STATUS, dmi) < 0) {
		err = -errno;
		fprintf(stderr, "DM_TABLE_STATUS failed, errno: %d\n", err);
		goto out;
	}
	if (dmi->flags & DM_BUFFER_FULL_FLAG) {
		err = -E2BIG;
		fprintf(stderr, "device-mapper table exceeds %u bytes\n",
			P2P_DM_BUFFER_SIZE);
		goto out;
	}

	*buffer_out = buffer;
	buffer = NULL;
	err = 0;
out:
	free(buffer);
	close(control_fd);
	return err;
}

static int discover_linear(const char *dev, dev_t top_dev,
			   struct topo_user_cfg *cfg)
{
	struct dm_target_spec *first;
	struct dm_target_spec *spec;
	struct dm_ioctl *dmi;
	unsigned long long logical_end = 0;
	char *limit;
	void *buffer = NULL;
	unsigned int i;
	int err;

	err = dm_table_query(top_dev, &buffer);
	if (err) {
		fprintf(stderr, "discover linear topology for %s failed: %d\n",
			dev, err);
		return err;
	}
	dmi = buffer;
	if (!(dmi->flags & DM_ACTIVE_PRESENT_FLAG) || !dmi->target_count ||
	    dmi->target_count > P2P_TOPO_MAX_BDEVS ||
	    dmi->data_size < sizeof(*dmi) ||
	    dmi->data_start < sizeof(*dmi) || dmi->data_start >= dmi->data_size) {
		err = dmi->target_count > P2P_TOPO_MAX_BDEVS ? -E2BIG : -EINVAL;
		goto out;
	}

	limit = (char *)buffer + dmi->data_size;
	first = (void *)((char *)buffer + dmi->data_start);
	spec = first;
	strcpy(cfg->name, "linear");
	cfg->nr_devs = dmi->target_count;
	cfg->top_dev = top_dev;

	for (i = 0; i < cfg->nr_devs; i++) {
		struct topo_user_bdev *entry = &cfg->bdevs[i];
		unsigned long long start_sector;
		char *params;
		char *params_end;
		dev_t component;

		if ((char *)(spec + 1) > limit ||
		    !memchr(spec->target_type, '\0', sizeof(spec->target_type)) ||
		    strcmp(spec->target_type, "linear") || !spec->length ||
		    spec->sector_start != logical_end) {
			err = -EINVAL;
			goto out;
		}
		params = (char *)(spec + 1);
		if (i + 1 < cfg->nr_devs) {
			if (!spec->next || (char *)first + spec->next <= params ||
			    (char *)first + spec->next > limit) {
				err = -EINVAL;
				goto out;
			}
			params_end = (char *)first + spec->next;
		} else {
			params_end = limit;
		}
		if (!memchr(params, '\0', params_end - params)) {
			err = -EINVAL;
			goto out;
		}
		err = parse_linear_params(params, &component, &start_sector);
		if (err)
			goto out;
		entry->dev_id = component;
		entry->reserved = 0;
		entry->size_sector = spec->length;
		entry->start_sector = start_sector;
		if (__builtin_add_overflow(logical_end,
					   (unsigned long long)spec->length,
					   &logical_end)) {
			err = -EINVAL;
			goto out;
		}
		if (i + 1 < cfg->nr_devs)
			spec = (void *)((char *)first + spec->next);
	}
	err = 0;
out:
	free(buffer);
	return err;
}

static int compare_raid0_member_slot(const void *left, const void *right)
{
	const struct raid0_member *a = left;
	const struct raid0_member *b = right;

	return a->slot - b->slot;
}

static int read_member_value(int member_fd, const char *name,
			     unsigned long long *value)
{
	char text[64];
	int err;

	err = read_text_at(member_fd, name, text, sizeof(text));
	if (err)
		return err;
	*value = strtoull(text, NULL, 10);
	return 0;
}

static int read_raid0_member(int md_fd, const char *name,
			     unsigned int raid_disks,
			     struct raid0_member *member)
{
	unsigned long long start_sector;
	unsigned long long size_kb;
	char state[128];
	char block_dev[64];
	char slot_text[64];
	dev_t component;
	int slot;
	int member_fd;
	int err;

	member_fd = openat(md_fd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (member_fd < 0)
		return -errno;
	err = read_text_at(member_fd, "state", state, sizeof(state));
	if (err)
		goto out;
	state[strcspn(state, "\r\n")] = '\0';
	if (strcmp(state, "in_sync")) {
		err = 0;
		goto out;
	}

	err = read_text_at(member_fd, "slot", slot_text, sizeof(slot_text));
	if (err)
		goto out;
	slot_text[strcspn(slot_text, "\r\n")] = '\0';
	if (!strcmp(slot_text, "none")) {
		err = 0;
		goto out;
	}
	slot = atoi(slot_text);
	if (slot < 0 || slot >= (int)raid_disks) {
		err = -EINVAL;
		goto out;
	}
	err = read_member_value(member_fd, "offset", &start_sector);
	if (err)
		goto out;
	err = read_member_value(member_fd, "size", &size_kb);
	if (err)
		goto out;
	if (!size_kb) {
		err = -EINVAL;
		goto out;
	}
	err = read_text_at(member_fd, "block/dev", block_dev,
			   sizeof(block_dev));
	if (err)
		goto out;
	err = parse_devt(block_dev, &component);
	if (err)
		goto out;
	err = validate_nvme_component_input(component);
	if (err)
		goto out;

	/*
	 * member is stack-allocated by the caller; zero reserved so
	 * topo_validate_cfg does not reject uninitialized garbage.
	 */
	memset(member, 0, sizeof(*member));
	member->slot = slot;
	member->bdev.dev_id = component;
	member->bdev.size_sector = size_kb * P2P_SECTORS_PER_KB;
	member->bdev.start_sector = start_sector;
	err = 1;
out:
	close(member_fd);
	return err;
}

static int discover_raid0_members(dev_t top_dev, unsigned int raid_disks,
				  struct topo_user_cfg *cfg)
{
	struct raid0_member members[P2P_TOPO_MAX_BDEVS];
	char md_path[PATH_MAX];
	struct dirent *dirent;
	unsigned int active = 0;
	unsigned int i;
	DIR *dir;
	int dir_fd;
	int err;

	memset(members, 0, sizeof(members));
	err = sysfs_path(md_path, sizeof(md_path), top_dev, "md");
	if (err)
		return err;
	dir_fd = open(md_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dir_fd < 0)
		return -errno;
	dir = fdopendir(dir_fd);
	if (!dir) {
		err = -errno;
		close(dir_fd);
		return err;
	}

	for (;;) {
		struct raid0_member member;

		errno = 0;
		dirent = readdir(dir);
		if (!dirent) {
			if (errno) {
				err = -errno;
				goto out;
			}
			break;
		}
		if (strncmp(dirent->d_name, "dev-", 4))
			continue;
		err = read_raid0_member(dirfd(dir), dirent->d_name, raid_disks,
					&member);
		if (err < 0)
			goto out;
		if (!err)
			continue;
		if (active >= raid_disks) {
			err = -EINVAL;
			goto out;
		}
		members[active++] = member;
	}
	if (active != raid_disks) {
		fprintf(stderr, "RAID0 has %u in-sync members, expected %u\n",
			active, raid_disks);
		err = -EINVAL;
		goto out;
	}

	qsort(members, active, sizeof(members[0]), compare_raid0_member_slot);
	for (i = 0; i < active; i++) {
		if (members[i].slot != (int)i) {
			fprintf(stderr, "RAID0 slot %u is missing or duplicated\n", i);
			err = -EINVAL;
			goto out;
		}
		cfg->bdevs[i] = members[i].bdev;
	}
	err = 0;
out:
	closedir(dir);
	return err;
}

static int discover_raid0(const char *dev, dev_t top_dev,
			  struct topo_user_cfg *cfg)
{
	unsigned long long chunk_bytes;
	unsigned long long chunk_sectors;
	unsigned long long raid_disks;
	char level[64];
	unsigned int shift = 0;
	int err;

	err = read_sysfs_text(top_dev, "md/level", level, sizeof(level));
	if (err)
		return err;
	level[strcspn(level, "\r\n")] = '\0';
	if (strcmp(level, "raid0")) {
		fprintf(stderr, "%s uses unsupported MD level %s\n", dev, level);
		return -EOPNOTSUPP;
	}
	err = read_sysfs_u64(top_dev, "md/chunk_size", &chunk_bytes);
	if (err)
		return err;
	err = read_sysfs_u64(top_dev, "md/raid_disks", &raid_disks);
	if (err)
		return err;
	if (raid_disks < 2 || raid_disks > P2P_TOPO_MAX_BDEVS)
		return raid_disks > P2P_TOPO_MAX_BDEVS ? -E2BIG : -EINVAL;
	if (!chunk_bytes || chunk_bytes % P2P_SECTOR_SIZE)
		return -EINVAL;
	chunk_sectors = chunk_bytes / P2P_SECTOR_SIZE;
	if (!chunk_sectors || (chunk_sectors & (chunk_sectors - 1)))
		return -EINVAL;
	while ((1ULL << shift) != chunk_sectors) {
		if (++shift >= 32)
			return -EINVAL;
	}

	strcpy(cfg->name, "raid0");
	cfg->nr_devs = raid_disks;
	cfg->extra[0] = shift;
	cfg->top_dev = top_dev;
	err = discover_raid0_members(top_dev, raid_disks, cfg);
	if (err)
		fprintf(stderr, "discover RAID0 members for %s failed: %d\n",
			dev, err);
	return err;
}

static void print_topo_cfg(const struct topo_user_cfg *cfg)
{
	unsigned int i;

	printf("topo: name=%s top_dev=%u:%u nr_devs=%u extra={%llu,%llu}\n",
	       cfg->name, major(cfg->top_dev), minor(cfg->top_dev), cfg->nr_devs,
	       (unsigned long long)cfg->extra[0],
	       (unsigned long long)cfg->extra[1]);
	for (i = 0; i < cfg->nr_devs; i++) {
		const struct topo_user_bdev *bdev = &cfg->bdevs[i];

		printf("  bdev[%u]: dev=%u:%u start_sector=%llu "
		       "size_sector=%llu\n", i, major(bdev->dev_id),
		       minor(bdev->dev_id),
		       (unsigned long long)bdev->start_sector,
		       (unsigned long long)bdev->size_sector);
	}
}

int p2p_add_topo(int dev_fd, const char *dev)
{
	struct topo_user_cfg *cfg = NULL;
	struct stat st;
	size_t cfg_size;
	int (*discover)(const char *, dev_t, struct topo_user_cfg *);
	int err;

	if (stat(dev, &st) < 0)
		return -errno;
	if (!S_ISBLK(st.st_mode))
		return -EINVAL;
	if (path_exists(st.st_rdev, "partition") ||
	    path_exists(st.st_rdev, "device/subsysnqn"))
		discover = discover_nvme;
	else if (path_exists(st.st_rdev, "dm"))
		discover = discover_linear;
	else if (path_exists(st.st_rdev, "md"))
		discover = discover_raid0;
	else
		return -EOPNOTSUPP;

	cfg_size = sizeof(*cfg) +
		   P2P_TOPO_MAX_BDEVS * sizeof(cfg->bdevs[0]);
	cfg = calloc(1, cfg_size);
	if (!cfg) {
		err = -ENOMEM;
		goto out;
	}
	err = discover(dev, st.st_rdev, cfg);
	if (err)
		goto out;
	print_topo_cfg(cfg);
	if (ioctl(dev_fd, IOCTL_ADD_TOPO, cfg) < 0) {
		err = -errno;
		fprintf(stderr, "add topology for %s failed, errno: %d\n",
			dev, err);
	} else {
		err = 0;
	}
out:
	free(cfg);
	return err;
}

static unsigned long long align_down_u64(unsigned long long value,
					 unsigned int alignment)
{
	return value & ~((unsigned long long)alignment - 1);
}

static unsigned long long align_up_u64(unsigned long long value,
				       unsigned int alignment)
{
	return (value + alignment - 1) & ~((unsigned long long)alignment - 1);
}

static int calc_fiemap_extent_count(unsigned long offset, unsigned long size,
				    unsigned int block_size,
				    unsigned int *count)
{
	unsigned long long block_offset = offset & (block_size - 1);
	unsigned long long blocks;

	blocks = align_up_u64(block_offset + size, block_size) / block_size;
	if (!blocks)
		blocks = 1;
	if (blocks > UINT_MAX)
		return -E2BIG;

	*count = blocks;
	return 0;
}

static struct fiemap *alloc_fiemap(unsigned int extent_count)
{
	return calloc(1, sizeof(struct fiemap) +
		      extent_count * sizeof(struct fiemap_extent));
}

static int is_sector_aligned(unsigned long long value)
{
	return !(value & (P2P_SECTOR_SIZE - 1));
}

static int trim_fiemap_extents(struct fiemap_extent *extents,
			       unsigned int ext_num, unsigned long offset,
			       unsigned long size, unsigned int *trimmed_ext_num,
			       unsigned long long *total_size)
{
	unsigned long long request_start = offset;
	unsigned long long request_end = request_start + size;
	unsigned long long total = 0;
	unsigned int out = 0;
	unsigned int i;

	for (i = 0; i < ext_num; i++) {
		struct fiemap_extent extent = extents[i];
		unsigned long long extent_start = extent.fe_logical;
		unsigned long long extent_end = extent_start + extent.fe_length;
		unsigned long long trim_start;
		unsigned long long trim_end;

		if (extent_end <= request_start || extent_start >= request_end)
			continue;
		if (extent.fe_flags & P2P_UNSUPPORTED_FIEMAP_FLAGS) {
			fprintf(stderr,
				"unsupported FIEMAP extent flags 0x%x at extent %u\n",
				extent.fe_flags, i);
			return -EOPNOTSUPP;
		}

		trim_start = extent_start > request_start ?
			     extent_start : request_start;
		trim_end = extent_end < request_end ? extent_end : request_end;
		if (trim_end <= trim_start)
			continue;

		extent.fe_physical += trim_start - extent_start;
		extent.fe_logical = trim_start;
		extent.fe_length = trim_end - trim_start;
		extents[out++] = extent;
		total += extent.fe_length;
	}

	*trimmed_ext_num = out;
	*total_size = total;
	return 0;
}

int p2p_prepare_io_extents(int file_fd, const struct stat *file_stat,
			   unsigned long offset, unsigned long size,
			   struct fiemap **exts_out, unsigned int *ext_num_out,
			   unsigned long long *total_size_out)
{
	struct fiemap *exts;
	unsigned int block_size;
	unsigned int max_num;
	unsigned long long query_start;
	unsigned long long query_offset;
	unsigned long long query_length;
	int err;

	if (S_ISBLK(file_stat->st_mode)) {
		if (!is_sector_aligned(offset) || !is_sector_aligned(size))
			return -EINVAL;

		exts = alloc_fiemap(1);
		if (!exts)
			return -ENOMEM;

		exts->fm_extents[0].fe_logical = offset;
		exts->fm_extents[0].fe_physical = offset;
		exts->fm_extents[0].fe_length = size;
		*exts_out = exts;
		*ext_num_out = 1;
		*total_size_out = size;
		return 0;
	}

	if (!S_ISREG(file_stat->st_mode))
		return -EINVAL;

	block_size = file_stat->st_blksize;
	err = calc_fiemap_extent_count(offset, size, block_size, &max_num);
	if (err)
		return err;

	exts = alloc_fiemap(max_num);
	if (!exts)
		return -ENOMEM;

	query_start = align_down_u64(offset, block_size);
	query_offset = offset - query_start;
	query_length = align_up_u64(query_offset + size, block_size);

	exts->fm_start = query_start;
	exts->fm_length = query_length;
	exts->fm_flags = 0;
	exts->fm_extent_count = max_num;

	err = ioctl(file_fd, FS_IOC_FIEMAP, exts);
	if (err) {
		err = -errno;
		fprintf(stderr, "ioctl FS_IOC_FIEMAP failed, errno: %d\n", err);
		free(exts);
		return err;
	}

	err = trim_fiemap_extents(exts->fm_extents, exts->fm_mapped_extents,
				  offset, size, ext_num_out, total_size_out);
	if (err) {
		free(exts);
		return err;
	}
	*exts_out = exts;
	return 0;
}

int p2p_get_iov_size(const struct p2p_iov *iov, unsigned int iov_nr,
		     unsigned long *size_out)
{
	unsigned long size = 0;
	unsigned int i;

	if (!iov || !iov_nr)
		return -EINVAL;

	for (i = 0; i < iov_nr; i++) {
		if (!iov[i].size || iov[i].reserved ||
		    ((iov[i].addr | iov[i].size) &
		     (P2P_SECTOR_SIZE - 1)) ||
		    UINT64_MAX - iov[i].addr < iov[i].size ||
		    ULONG_MAX - size < iov[i].size)
			return -EINVAL;
		size += iov[i].size;
	}

	*size_out = size;
	return 0;
}
