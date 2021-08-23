/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021. Huawei Technologies Co., Ltd. All rights reserved.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef EUFS_NVM_STRUCT_H
#define EUFS_NVM_STRUCT_H

#define EUFS_SB_SIZE 512
#define EUFS_SB2_OFFSET 512
#define EUFS_SB_PADDING (1024 * 2)

/* Used by rename journal */
#define EUFS_MAX_CPU_CNT 128
#define EUFS_RENAMEJ_ENTRY_SIZE (1024)
#define EUFS_RENAMEJ_SIZE (EUFS_MAX_CPU_CNT * EUFS_RENAMEJ_ENTRY_SIZE)
#define EUFS_RENAMEJ_OFFSET (EUFS_SB_SIZE * 2 + EUFS_SB_PADDING)

#define EUFS_CRC_SEED (~0)
#define EUFS_RENAME_IN_ACTION 1

/*
 * Layout
 * +------------------------+
 * |  Super Block           | 64B
 * +------------------------+
 * |  Padding               | 512B-64B
 * +------------------------+
 * |  Seconary Super Block  | 64B
 * +------------------------+
 * |  Padding               | Aligned to 4K
 * +------------------------+
 *
 * +------------------------+
 * |                        |
 * | pages                  |
 * |                        |
 * +------------------------+
 * | bitmap for pages       | 4K-aligned
 * +------------------------+
 * |  Rename-Journals       | 128K (128 cores * 1024B/core)
 * +------------------------+
 * |                        |
 * | pages                  |
 * |                        |
 * +------------------------+
 */
/*
 * Structure of the EulerFS super block.
 */
struct eufs_super_block {
	/* checksum of this sb */
	__le16 s_sum;
	/* magic signature */
	__le16 s_magic;
	char s_safe_umount;
	char s_flag;
	__le16 s_fs_version;
	/* 8 Bytes */

	/* total size of fs in bytes */
	__le64 s_size;
	/* base virtual address used in fs */
	__le64 s_virt_addr;
	/* 24 Bytes */

	char s_volume_name[16];
	/* 40 Bytes */

	/* points to the location of mini-journal and rename journal */
	__le64 s_page_map;
	/* 48 Bytes */

	/*
	 * s_mtime(mount time) and s_wtime(write time) should be together and
	 * their order should not be changed. we use an 8 byte write to update
	 * both of them atomically.
	 */
	__le32 s_mtime;
	__le32 s_wtime;
	/* 56 Bytes */

	__le64 s_root_pi;
	/* 64 Bytes */
	__le64 s_crash_ver;
};

/* ========== directory & hash ========== */
#define FIRST_LEN (CACHELINE_SIZE - sizeof(__le64) * 5)
#define FOLLOW_LEN (CACHELINE_SIZE - sizeof(__le64))

typedef u64 hashlen_t;
struct nv_dict {
	__le64 __pmem table[NV_DICT_CAPACITY]; /* <struct nv_dict_entry *> */
} __aligned(PAGE_SIZE);

struct nv_dict_entry {
	/* half a cache line (8B * 4) size in total */
	__le64 inode; /* <struct eufs_inode *> */
	__le64 next; /* <struct nv_dict_entry *> */
	__le64 volatile_next; /* <struct nv_dict_entry *> */
	/* store some filename */
	__le64 hv; /* <hashlen_t> hashlen */
	__le64 nextname; /* <char *> */
	char name[FIRST_LEN];
} __aligned(CACHELINE_SIZE);

struct nv_name_ext {
	char name[FOLLOW_LEN];
	__le64 nextname;
} __aligned(CACHELINE_SIZE);

#define EUFS_IS_HEAD_PI(pi) (!((u64)(pi) & (0x100 - 1)))

#define EUFS_TWIN_PI(pi)                                                      \
	(EUFS_IS_HEAD_PI(pi) ? (((struct eufs_inode *)(pi)) + 1) :           \
				(((struct eufs_inode *)(pi)) - 1))

#define EUFS_FRESH_PI(pi)                                                     \
	(((pi)->i_fresh >= EUFS_TWIN_PI(pi)->i_fresh) ? (pi) :                \
							 EUFS_TWIN_PI(pi))

#define EUFS_HEAD_PI(pi) (EUFS_IS_HEAD_PI(pi) ? (pi) : EUFS_TWIN_PI(pi))

/* ========== inode ========== */
struct eufs_inode {
	/* Cacheline 1: readmost part */
	/* 0 ~ 8 */
	__le32 i_flags; /* Inode flags */
	__le16 i_mode; /* File mode */
	__le16 i_version; /* Inode version */
	/* 8 ~ 16 */
	/* Note: the ctime to report is max(i_ctime, i_mtime) */
	__le64 i_ctime; /* Inode modification time (only for metadata) */
	/* 16 ~ 24 */
	__le32 i_uid; /* Owner Uid */
	__le32 i_gid; /* Group Id */
	/* 24 ~ 32 */
	__le64 i_dotdot; /* <struct eufs_inode *> parent inode (dir only) */
	/* 32 ~ 40 */
	__le64 i_ext; /* reserved for extension */
	/* 40 ~ 48 */
	__le32 i_ctime_nsec; /* nano sec */
	/* 48 ~ 56 */
	__le64 padding1;
	/* 56 ~ 64 */
	__le64 padding2;

	/* Cacheline 2: readmost part */
	/* readwirte part */
	/* 0 ~ 8 */
	__le32 i_generation; /* File version (for NFS) */
	__le16 i_nlink; /* Links count */
	/*
	 * Freshness: we have twin-inodes here. When we access an inode,
	 * we compare the freshness of the two inodes and use the one with
	 * higher freshness. The freshness is only 16-bit, but we can easily
	 * handle the overflow.
	 */
	__le16 i_fresh; /* Freshness of the inode */
	/* 8 ~ 16 */
	__le64 i_mtime; /* Inode b-tree Modification time */
	/* 16 ~ 24 */
	__le64 i_atime; /* Access time */
	/* 24 ~ 32 */
	union {
		__le64 i_root; /* btree root (regular only) */
		__le64 i_dict; /* dict root (dir only */
		__le32 i_rdev; /* major/minor (device only) */
	};
	/* 32 ~ 40 */
	/*
	 * Size:
	 * for directory: number of entries inside
	 * for regular: number of bytes stored
	 * others: not used
	 */
	__le64 i_size; /* Size of data in bytes */
	/* 40 ~ 48 */
	__le64 i_tree_blocks; /* #blocks allocated in btree (regular only) */

	/* 48 ~ 56 */
	__le32 i_mtime_nsec; /* nano sec */
	__le32 i_atime_nsec; /* nano sec */
	/* 56 ~ 64 */
	__le64 padding3;
} __aligned(CACHELINE_SIZE);

#define eufs_iread_flags(i) (le32_to_cpu((i)->i_flags))
#define eufs_iread_mode(i) (le16_to_cpu((i)->i_mode))
#define eufs_iread_ctime(i) (le64_to_cpu((i)->i_ctime))
#define eufs_iread_uid(i) (le32_to_cpu((i)->i_uid))
#define eufs_iread_gid(i) (le32_to_cpu((i)->i_gid))
#define eufs_iread_dotdot(i) (le64_to_cpu((i)->i_dotdot))

#define eufs_iwrite_flags(i, v) ((i)->i_flags = cpu_to_le32(v))
#define eufs_iwrite_mode(i, v) ((i)->i_mode = cpu_to_le16(v))
#define eufs_iwrite_ctime(i, v) ((i)->i_ctime = cpu_to_le64(v))
#define eufs_iwrite_uid(i, v) ((i)->i_uid = cpu_to_le32(v))
#define eufs_iwrite_gid(i, v) ((i)->i_gid = cpu_to_le32(v))
#define eufs_iwrite_dotdot(i, v) ((i)->i_dotdot = cpu_to_le64(v))

#define eufs_iread_version(i) (le16_to_cpu((i)->i_version))
#define eufs_iread_ctime_nsec(i) (le32_to_cpu((i)->i_ctime_nsec))
#define eufs_iread_ext(i) (le64_to_cpu((i)->i_ext))
#define eufs_iwrite_version(i, v) ((i)->i_version = cpu_to_le16(v))
#define eufs_iwrite_ctime_nsec(i, v) ((i)->i_ctime_nsec = cpu_to_le32(v))
#define eufs_iwrite_ext(i, v) ((i)->i_ext = cpu_to_le64(v))

#define eufs_writemostly_inode(i) ((i))

#define eufs_iread_generation(i)                                              \
	(le32_to_cpu(eufs_writemostly_inode(i)->i_generation))
#define eufs_iread_nlink(i) (le16_to_cpu(eufs_writemostly_inode(i)->i_nlink))
#define eufs_iread_mtime(i) (le64_to_cpu(eufs_writemostly_inode(i)->i_mtime))
#define eufs_iread_atime(i) (le64_to_cpu(eufs_writemostly_inode(i)->i_atime))
#define eufs_iread_root(i) (le64_to_cpu(eufs_writemostly_inode(i)->i_root))
#define eufs_iread_dict(i) (le64_to_cpu(eufs_writemostly_inode(i)->i_dict))
#define eufs_iread_rdev(i) (le32_to_cpu(eufs_writemostly_inode(i)->i_rdev))
#define eufs_iread_size(i) (le64_to_cpu(eufs_writemostly_inode(i)->i_size))
#define eufs_iread_tree_blocks(i)                                             \
	(le64_to_cpu(eufs_writemostly_inode(i)->i_tree_blocks))

#define eufs_iwrite_generation(i, v)                                          \
	(eufs_writemostly_inode(i)->i_generation = cpu_to_le32(v))
#define eufs_iwrite_nlink(i, v)                                               \
	(eufs_writemostly_inode(i)->i_nlink = cpu_to_le16(v))
#define eufs_iwrite_mtime(i, v)                                               \
	(eufs_writemostly_inode(i)->i_mtime = cpu_to_le64(v))
#define eufs_iwrite_atime(i, v)                                               \
	(eufs_writemostly_inode(i)->i_atime = cpu_to_le64(v))
#define eufs_iwrite_root(i, v)                                                \
	(eufs_writemostly_inode(i)->i_root = cpu_to_le64(v))
#define eufs_iwrite_dict(i, v)                                                \
	(eufs_writemostly_inode(i)->i_dict = cpu_to_le64(v))
#define eufs_iwrite_rdev(i, v)                                                \
	(eufs_writemostly_inode(i)->i_rdev = cpu_to_le32(v))
#define eufs_iwrite_size(i, v)                                                \
	(eufs_writemostly_inode(i)->i_size = cpu_to_le64(v))
#define eufs_iwrite_tree_blocks(i, v)                                         \
	(eufs_writemostly_inode(i)->i_tree_blocks = cpu_to_le64(v))

#define eufs_iread_mtime_nsec(i)                                              \
	(le32_to_cpu(eufs_writemostly_inode(i)->i_mtime_nsec))
#define eufs_iread_atime_nsec(i)                                              \
	(le32_to_cpu(eufs_writemostly_inode(i)->i_atime_nsec))
#define eufs_iwrite_mtime_nsec(i, v)                                          \
	(eufs_writemostly_inode(i)->i_mtime_nsec = cpu_to_le32(v))
#define eufs_iwrite_atime_nsec(i, v)                                          \
	(eufs_writemostly_inode(i)->i_atime_nsec = cpu_to_le32(v))

static inline void eufs_iwrite_ctime_mtime(struct eufs_inode *pi,
					    struct inode *vi)
{
	eufs_iwrite_ctime(pi, vi->i_ctime.tv_sec);
	eufs_iwrite_ctime_nsec(pi, vi->i_ctime.tv_nsec);

	eufs_iwrite_mtime(pi, vi->i_mtime.tv_sec);
	eufs_iwrite_mtime_nsec(pi, vi->i_mtime.tv_nsec);
}

struct eufs_renamej {
	__le32 crc;
	__le32 flags;
	__le64 addr_of_oldnext;
	__le64 oldnext;
	__le64 addr_of_newde;
	__le64 composed_newde; /* composed as list header */
	__le64 newde_inode;
	__le64 old_dir_pi;
	__le64 new_dir_pi;

	__le64 time;
	__le32 time_nsec;
	__le16 old_link;
	__le16 new_link;
	__le32 old_size;
	__le32 new_size;
	__u8 pad[40];
} __aligned(CACHELINE_SIZE);

typedef u8 page_info_t;
typedef u8 line_info_t;

struct embedded_line_info {
	line_info_t gens[64];
};

#endif /* EUFS_NVM_STRUCT_H */
