// SPDX-License-Identifier: GPL-2.0
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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

#define P2P_LOOP_UNSUPPORTED_FIEMAP_FLAGS \
	(FIEMAP_EXTENT_UNKNOWN | FIEMAP_EXTENT_DELALLOC | \
	 FIEMAP_EXTENT_ENCODED | FIEMAP_EXTENT_DATA_ENCRYPTED | \
	 FIEMAP_EXTENT_NOT_ALIGNED | FIEMAP_EXTENT_DATA_INLINE | \
	 FIEMAP_EXTENT_DATA_TAIL | FIEMAP_EXTENT_SHARED)

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

int p2p_check_uapi(int dev_fd, uint32_t *version_out)
{
	struct p2p_device_info info = { 0 };
	int err;

	if (ioctl(dev_fd, IOCTL_GET_INFO, &info) < 0) {
		err = errno;
		return (err == ENOTTY || err == EINVAL) ? -EPROTONOSUPPORT : -err;
	}
	if (info.version != P2P_UAPI_VERSION) {
		fprintf(stderr,
			"p2p UAPI version mismatch: driver v%u.%u, library v%u.%u\n",
			(info.version >> 8) & 0xffU, info.version & 0xffU,
			P2P_UAPI_VERSION_MAJOR, P2P_UAPI_VERSION_MINOR);
		return -EPROTONOSUPPORT;
	}
	*version_out = info.version;
	return 0;
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

static int get_block_size_sectors(dev_t dev_id, uint64_t *size_sectors)
{
	unsigned long long size;
	int err;

	err = read_sysfs_u64(dev_id, "size", &size);
	if (err)
		return err;
	if (!size) {
		fprintf(stderr, "invalid block-device size for %u:%u\n",
			major(dev_id), minor(dev_id));
		return -EINVAL;
	}

	*size_sectors = size;
	return 0;
}

static int discover_nvme(dev_t top_dev, struct topo_user_cfg *cfg)
{
	uint64_t size_sectors = 0;
	int err;

	err = validate_nvme_component_input(top_dev);
	if (err)
		return err;
	err = get_block_size_sectors(top_dev, &size_sectors);
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

static int discover_linear(dev_t top_dev, struct topo_user_cfg *cfg)
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
		fprintf(stderr,
			"discover linear topology for %u:%u failed: %d\n",
			major(top_dev), minor(top_dev), err);
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

static int discover_raid0(dev_t top_dev, struct topo_user_cfg *cfg)
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
		fprintf(stderr, "%u:%u uses unsupported MD level %s\n",
			major(top_dev), minor(top_dev), level);
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
		fprintf(stderr,
			"discover RAID0 members for %u:%u failed: %d\n",
			major(top_dev), minor(top_dev), err);
	return err;
}

typedef int (*topo_discover_fn)(dev_t,
				struct topo_user_cfg *);

static topo_discover_fn select_discover(dev_t devt)
{
	if (path_exists(devt, "partition") ||
	    path_exists(devt, "device/subsysnqn"))
		return discover_nvme;
	if (path_exists(devt, "dm"))
		return discover_linear;
	if (path_exists(devt, "md"))
		return discover_raid0;
	return NULL;
}

static int devt_to_bdev(dev_t devt, char *bdev, size_t bdev_size)
{
	char sys[64];
	char link[PATH_MAX];
	const char *base;
	ssize_t len;

	if (snprintf(sys, sizeof(sys), "/sys/dev/block/%u:%u",
		     major(devt), minor(devt)) >= (int)sizeof(sys))
		return -ENAMETOOLONG;
	len = readlink(sys, link, sizeof(link) - 1);
	if (len < 0)
		return -errno;
	link[len] = '\0';
	base = strrchr(link, '/');
	base = base ? base + 1 : link;
	if (snprintf(bdev, bdev_size, "/dev/%s", base) >= (int)bdev_size)
		return -ENAMETOOLONG;
	return 0;
}

static int map_topology_sector(const struct topo_user_cfg *topology,
			       uint64_t from_sector, uint64_t requested,
			       uint32_t *dev_index,
			       uint64_t *component_sector,
			       uint64_t *mapped)
{
	uint64_t available;

	if (!strcmp(topology->name, "nvme")) {
		if (from_sector >= topology->bdevs[0].size_sector)
			return -EINVAL;
		*dev_index = 0;
		*component_sector = from_sector;
		available = topology->bdevs[0].size_sector - from_sector;
	} else if (!strcmp(topology->name, "linear")) {
		uint64_t logical_start = 0;
		uint32_t i;

		for (i = 0; i < topology->nr_devs; i++) {
			uint64_t size = topology->bdevs[i].size_sector;

			if (from_sector - logical_start >= size) {
				logical_start += size;
				continue;
			}
			*dev_index = i;
			*component_sector = from_sector - logical_start;
			available = size - *component_sector;
			goto found;
		}
		return -EINVAL;
	} else if (!strcmp(topology->name, "raid0")) {
		uint64_t chunk = 1ULL << topology->extra[0];
		uint64_t chunk_index = from_sector >> topology->extra[0];
		uint64_t chunk_offset = from_sector & (chunk - 1);

		*dev_index = chunk_index % topology->nr_devs;
		*component_sector =
			(chunk_index / topology->nr_devs) * chunk + chunk_offset;
		available = chunk - chunk_offset;
	} else {
		return -EOPNOTSUPP;
	}

found:
	*mapped = requested < available ? requested : available;
	return 0;
}

static int append_loop_extent(struct topo_user_cfg *cfg, uint32_t dev_index,
			      uint64_t start_sector, uint64_t size_sector,
			      uint32_t flags)
{
	struct topo_user_extent *extents = topo_user_loop_extents(cfg);
	struct topo_user_extent *previous;
	uint64_t previous_end;
	uint64_t count = cfg->extra[0];

	if (count) {
		previous = &extents[count - 1];
		if (!__builtin_add_overflow(previous->start_sector,
					    previous->size_sector,
					    &previous_end) &&
		    previous->dev_index == dev_index &&
		    previous->reserved == flags &&
		    previous_end == start_sector) {
			if (__builtin_add_overflow(previous->size_sector,
					   size_sector,
					   &previous->size_sector))
				return -EOVERFLOW;
			return 0;
		}
	}
	if (count >= P2P_TOPO_MAX_EXTENTS)
		return -E2BIG;
	extents[count].dev_index = dev_index;
	extents[count].reserved = flags;
	extents[count].size_sector = size_sector;
	extents[count].start_sector = start_sector;
	cfg->extra[0]++;
	return 0;
}

static int append_striped_loop_extent(struct topo_user_cfg *cfg,
				      const struct topo_user_cfg *underlying,
				      uint64_t physical_sector,
				      uint64_t size_sector, uint32_t flags)
{
	uint64_t raid_sectors;
	uint64_t end;

	/*
	 * Keep this as one logical range on the RAID0 set. Splitting every
	 * chunk into its own extent makes mapping walk the whole prefix.
	 */
	if (underlying->nr_devs < 2 || underlying->extra[0] >= 32)
		return -EINVAL;
	if (__builtin_mul_overflow(underlying->bdevs[0].size_sector,
				   (uint64_t)underlying->nr_devs,
				   &raid_sectors) ||
	    __builtin_add_overflow(physical_sector, size_sector, &end) ||
	    end > raid_sectors)
		return -EINVAL;
	return append_loop_extent(cfg, 0, physical_sector, size_sector, flags);
}

static int flatten_loop_extent(struct topo_user_cfg *cfg,
			       const struct topo_user_cfg *underlying,
			       uint64_t physical_sector,
			       uint64_t size_sector, uint32_t flags)
{
	if (!strcmp(underlying->name, "raid0"))
		return append_striped_loop_extent(cfg, underlying,
						  physical_sector, size_sector,
						  flags);

	while (size_sector) {
		uint64_t component_sector;
		uint64_t mapped;
		uint32_t dev_index;
		int err;

		err = map_topology_sector(underlying, physical_sector, size_sector,
					  &dev_index, &component_sector, &mapped);
		if (err)
			return err;
		err = append_loop_extent(cfg, dev_index, component_sector, mapped,
					 flags);
		if (err)
			return err;
		physical_sector += mapped;
		size_sector -= mapped;
	}
	return 0;
}

static int discover_loop_extents(int backing_fd, uint64_t backing_offset,
				 uint64_t loop_size,
				 const struct topo_user_cfg *underlying,
				 struct topo_user_cfg *cfg)
{
	struct fiemap *fiemap;
	uint64_t backing_end;
	uint64_t expected;
	size_t size;
	uint32_t i;
	int err = 0;

	if (__builtin_add_overflow(backing_offset, loop_size, &backing_end))
		return -EOVERFLOW;
	size = sizeof(*fiemap) + P2P_TOPO_MAX_EXTENTS *
				 sizeof(fiemap->fm_extents[0]);
	fiemap = calloc(1, size);
	if (!fiemap)
		return -ENOMEM;
	fiemap->fm_start = backing_offset;
	fiemap->fm_length = loop_size;
	fiemap->fm_flags = FIEMAP_FLAG_SYNC;
	fiemap->fm_extent_count = P2P_TOPO_MAX_EXTENTS;
	if (ioctl(backing_fd, FS_IOC_FIEMAP, fiemap) < 0) {
		err = -errno;
		goto out;
	}
	if (!fiemap->fm_mapped_extents) {
		err = -ENODATA;
		goto out;
	}
	if (fiemap->fm_mapped_extents == P2P_TOPO_MAX_EXTENTS &&
	    !(fiemap->fm_extents[fiemap->fm_mapped_extents - 1].fe_flags &
	      FIEMAP_EXTENT_LAST)) {
		err = -E2BIG;
		goto out;
	}

	expected = backing_offset;
	for (i = 0; i < fiemap->fm_mapped_extents && expected < backing_end; i++) {
		const struct fiemap_extent *extent = &fiemap->fm_extents[i];
		uint64_t logical_start = extent->fe_logical;
		uint64_t logical_end;
		uint64_t physical;
		uint64_t length;

		if (extent->fe_flags & P2P_LOOP_UNSUPPORTED_FIEMAP_FLAGS ||
		    __builtin_add_overflow(extent->fe_logical, extent->fe_length,
					   &logical_end)) {
			err = -EOPNOTSUPP;
			goto out;
		}
		if (logical_end <= backing_offset || logical_start >= backing_end)
			continue;
		if (logical_start < backing_offset)
			logical_start = backing_offset;
		if (logical_end > backing_end)
			logical_end = backing_end;
		if (logical_start != expected) {
			err = -ENODATA;
			goto out;
		}
		physical = extent->fe_physical +
			   logical_start - extent->fe_logical;
		length = logical_end - logical_start;
		if ((physical | length) & (P2P_SECTOR_SIZE - 1)) {
			err = -EINVAL;
			goto out;
		}
		err = flatten_loop_extent(cfg, underlying,
					  physical / P2P_SECTOR_SIZE,
					  length / P2P_SECTOR_SIZE,
					  (extent->fe_flags & FIEMAP_EXTENT_UNWRITTEN) ?
					  P2P_TOPO_EXTENT_UNWRITTEN : 0);
		if (err)
			goto out;
		expected = logical_end;
	}
	if (expected != backing_end)
		err = -ENODATA;
out:
	free(fiemap);
	return err;
}

static int discover_loop(dev_t top_dev,
			 struct topo_user_cfg *cfg)
{
	struct topo_user_cfg *underlying = NULL;
	topo_discover_fn discover;
	unsigned long long backing_offset;
	unsigned long long dio;
	uint64_t loop_sectors;
	uint64_t loop_size;
	char backing_path[PATH_MAX];
	char backing_bdev[PATH_MAX];
	struct stat backing_stat;
	int backing_fd = -1;
	int err;

	err = read_sysfs_u64(top_dev, "loop/dio", &dio);
	if (err || dio != 1)
		return err ? err : -EOPNOTSUPP;
	err = read_sysfs_u64(top_dev, "loop/offset", &backing_offset);
	if (err)
		return err;
	if (backing_offset & (P2P_SECTOR_SIZE - 1))
		return -EINVAL;
	err = read_sysfs_text(top_dev, "loop/backing_file", backing_path,
			      sizeof(backing_path));
	if (err)
		return err;
	backing_path[strcspn(backing_path, "\r\n")] = '\0';
	if (!backing_path[0])
		return -EINVAL;

	err = get_block_size_sectors(top_dev, &loop_sectors);
	if (err)
		return err;
	if (__builtin_mul_overflow(loop_sectors, (uint64_t)P2P_SECTOR_SIZE,
				   &loop_size))
		return -EOVERFLOW;
	backing_fd = open(backing_path, O_RDONLY | O_CLOEXEC);
	if (backing_fd < 0)
		return -errno;
	if (fstat(backing_fd, &backing_stat) < 0) {
		err = -errno;
		goto out;
	}
	if (!S_ISREG(backing_stat.st_mode) || backing_stat.st_size < 0 ||
	    backing_offset > (uint64_t)backing_stat.st_size ||
	    loop_size > (uint64_t)backing_stat.st_size - backing_offset) {
		err = -EINVAL;
		goto out;
	}

	discover = select_discover(backing_stat.st_dev);
	if (!discover) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = devt_to_bdev(backing_stat.st_dev, backing_bdev,
			   sizeof(backing_bdev));
	if (err)
		goto out;
	underlying = calloc(1, sizeof(*underlying) +
				P2P_TOPO_MAX_BDEVS * sizeof(underlying->bdevs[0]));
	if (!underlying) {
		err = -ENOMEM;
		goto out;
	}
	err = discover(backing_stat.st_dev, underlying);
	if (err)
		goto out;

	memcpy(cfg->bdevs, underlying->bdevs,
	       underlying->nr_devs * sizeof(cfg->bdevs[0]));
	memcpy(cfg->name, "loop", sizeof("loop"));
	cfg->top_dev = top_dev;
	cfg->nr_devs = underlying->nr_devs;
	cfg->extra[0] = 0;
	cfg->extra[1] = 0;
	if (!strcmp(underlying->name, "raid0")) {
		if (underlying->extra[0] >= 32) {
			err = -EINVAL;
			goto out;
		}
		/* 0 means component extents. A RAID0 shift of 0 is stored as 1. */
		cfg->extra[1] = underlying->extra[0] + 1;
	}
	err = discover_loop_extents(backing_fd, backing_offset, loop_size,
				    underlying, cfg);
out:
	free(underlying);
	if (backing_fd >= 0)
		close(backing_fd);
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
	if (!strcmp(cfg->name, "loop")) {
		const struct topo_user_extent *extents = topo_user_loop_extents(
			(struct topo_user_cfg *)cfg);
		unsigned long long unwritten = 0;

		for (i = 0; i < cfg->extra[0]; i++) {
			if (extents[i].reserved & P2P_TOPO_EXTENT_UNWRITTEN)
				unwritten++;
		}
		if (cfg->extra[1])
			printf("  loop extents: %llu unwritten: %llu raid0 chunk_shift: %llu\n",
			       (unsigned long long)cfg->extra[0], unwritten,
			       (unsigned long long)cfg->extra[1] - 1);
		else
			printf("  loop extents: %llu unwritten: %llu\n",
			       (unsigned long long)cfg->extra[0], unwritten);
	}
}

int p2p_add_topo(int dev_fd, dev_t dev_id)
{
	struct topo_user_cfg *cfg = NULL;
	size_t cfg_size;
	topo_discover_fn discover;
	int err;

	/* dev_fd is /dev/p2p_device. The block device to describe is dev_id. */
	if (!path_exists(dev_id, "dev"))
		return -EINVAL;
	if (path_exists(dev_id, "loop/backing_file"))
		discover = discover_loop;
	else
		discover = select_discover(dev_id);
	if (!discover)
		return -EOPNOTSUPP;

	cfg_size = sizeof(*cfg) +
		   P2P_TOPO_MAX_BDEVS * sizeof(cfg->bdevs[0]) +
		   P2P_TOPO_MAX_EXTENTS * sizeof(struct topo_user_extent);
	cfg = calloc(1, cfg_size);
	if (!cfg) {
		err = -ENOMEM;
		goto out;
	}
	err = discover(dev_id, cfg);
	if (err)
		goto out;
	print_topo_cfg(cfg);
	if (ioctl(dev_fd, IOCTL_ADD_TOPO, cfg) < 0) {
		err = -errno;
		fprintf(stderr, "add topology for %u:%u failed, errno: %d\n",
			major(dev_id), minor(dev_id), err);
	} else {
		err = 0;
	}
out:
	free(cfg);
	return err;
}

int p2p_del_topo(int dev_fd, dev_t dev_id)
{
	struct topo_del_cfg param = {
		.top_dev = dev_id,
		.reserved = 0,
	};

	if (ioctl(dev_fd, IOCTL_DEL_TOPO, &param) < 0)
		return -errno;
	return 0;
}

int p2p_del_topo_fd(int dev_fd, int topo_fd)
{
	struct stat st;
	dev_t top_dev;

	if (fstat(topo_fd, &st) < 0)
		return -errno;
	if (S_ISBLK(st.st_mode))
		top_dev = st.st_rdev;
	else if (S_ISREG(st.st_mode))
		top_dev = st.st_dev;
	else
		return -EINVAL;
	return p2p_del_topo(dev_fd, top_dev);
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
	return calloc(1, sizeof(struct fiemap) + extent_count * sizeof(struct fiemap_extent));
}

static int is_sector_aligned(unsigned long long value)
{
	return !(value & (P2P_SECTOR_SIZE - 1));
}

static int trim_fiemap_extents(struct fiemap_extent *extents, unsigned int ext_num, unsigned int op,
			       unsigned long offset, unsigned long size,
			       unsigned int *trimmed_ext_num, unsigned long long *total_size)
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
		if ((extent.fe_flags & ~P2P_FIEMAP_SUPPORTED_FLAGS) ||
		    (op == P2P_IO_WRITE && (extent.fe_flags & FIEMAP_EXTENT_SHARED))) {
			fprintf(stderr, "unsupported FIEMAP extent flags 0x%x at extent %u\n",
				extent.fe_flags, i);
			return -EOPNOTSUPP;
		}

		trim_start = extent_start > request_start ? extent_start : request_start;
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

int p2p_prepare_io_extents(int file_fd, const struct stat *file_stat, unsigned int op,
			   unsigned long offset, unsigned long size, struct fiemap **exts_out,
			   unsigned int *ext_num_out, unsigned long long *total_size_out)
{
	struct fiemap *exts;
	unsigned int block_size;
	unsigned int max_num;
	unsigned long long query_start;
	unsigned long long query_offset;
	unsigned long long query_length;
	int err;

	if (!size || !is_sector_aligned(offset) || !is_sector_aligned(size))
		return -EINVAL;
	/* File offsets are signed; reject overflow before changing the file. */
	if (offset > INT64_MAX || size > INT64_MAX - offset)
		return -EOVERFLOW;

	if (S_ISBLK(file_stat->st_mode)) {
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

	if (op == P2P_IO_WRITE) {
		if (fallocate(file_fd, 0, (off_t)offset, (off_t)size)) {
			err = -errno;
			fprintf(stderr, "fallocate fd %d offset %lu size %lu failed, errno: %d\n",
				file_fd, offset, size, err);
			goto free_exts;
		}
	}

	err = ioctl(file_fd, FS_IOC_FIEMAP, exts);
	if (err) {
		err = -errno;
		fprintf(stderr, "ioctl FS_IOC_FIEMAP failed, errno: %d\n", err);
		goto free_exts;
	}
	if (exts->fm_mapped_extents > max_num) {
		fprintf(stderr, "FIEMAP mapped extent count %u exceeds buffer capacity %u\n",
			exts->fm_mapped_extents, max_num);
		err = -EINVAL;
		goto free_exts;
	}

	err = trim_fiemap_extents(exts->fm_extents, exts->fm_mapped_extents, op, offset, size,
				  ext_num_out, total_size_out);
	if (err)
		goto free_exts;
	*exts_out = exts;
	return 0;

free_exts:
	free(exts);
	return err;
}

int p2p_get_iov_size(const struct p2p_iov *iov, unsigned int iov_nr, unsigned long *size_out)
{
	unsigned long size = 0;
	unsigned int i;

	if (!iov || !iov_nr)
		return -EINVAL;

	for (i = 0; i < iov_nr; i++) {
		if (!iov[i].size || iov[i].reserved ||
		    ((iov[i].addr | iov[i].size) & (P2P_SECTOR_SIZE - 1)) ||
		    UINT64_MAX - iov[i].addr < iov[i].size || ULONG_MAX - size < iov[i].size)
			return -EINVAL;
		size += iov[i].size;
	}

	*size_out = size;
	return 0;
}
