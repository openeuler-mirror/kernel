// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include "grc_hw_rdma.h"
#include "grc_gid.h"

#define grc_to_hw_addr(grc)  ((grc)->core_dev.hw_addr)
#define grc_cdev_to_hw_addr(cdev)  ((cdev)->hw_addr)

static u32 grc_rd32(u8 __iomem *addr, u64 reg)
{
	return readl(addr + (reg));
}

static void grc_wr32(u8 __iomem *addr, u64 reg, u32 value)
{
	writel((value), (addr + (reg)));
}

static void grc_read_regs(u8 __iomem *addr, u64 reg, u32 *data, u8 data_num)
{
	u32 i = 0;
	u32 *pdata = data;

	while (data_num) {
		*pdata = grc_rd32(addr, reg + i * sizeof(u32));
		data_num--;
		i++;
		pdata++;
	}
}

static void grc_write_regs(u8 __iomem *addr, u64 reg, const u32 *data, u8 data_num)
{
	u32 i = 0;

	while (data_num) {
		grc_wr32(addr, reg + i * sizeof(u32), *(data + i));
		data_num--;
		i++;
	}
}

static const struct nbl_hw_error_code hw_err_table[] = {
	/* reg_off, drop norm_cqe abnorm_cqe ae err_code */
	{/* 0x1000 */ 1, 0, 0, 0, 0x0},
	{/* 0x1004 */ 1, 0, 0, 0, 0x1},
	{/* 0x1008 */ 1, 0, 0, 0, 0x2},
	{/* 0x100c */ 1, 0, 0, 0, 0x3},
	{/* 0x1010 */ 1, 0, 0, 0, 0x4},
	{/* 0x1014 */ 1, 0, 0, 0, 0x5},
	{/* 0x1018 */ 1, 0, 0, 0, 0x6},
	{/* 0x101c */ 1, 0, 0, 0, 0x7},
	{/* 0x1020 */ 1, 0, 0, 0, 0x8},
	{/* 0x1024 */ 1, 0, 0, 0, 0x9},
	{/* 0x1028 */ 1, 0, 0, 0, 0xA},
	{/* 0x102c */ 1, 0, 0, 0, 0xB},
	{/* 0x1030 */ 0, 0, 0, 1, 0xC},
	{/* 0x1034 */ 0, 0, 0, 1, 0xD},
	{/* 0x1038 */ 0, 0, 0, 1, 0xE},
	{/* 0x103c */ 0, 0, 0, 1, 0xF},
	{/* 0x1040 */ 0, 0, 0, 1, 0x10},
	{/* 0x1044 */ 0, 0, 0, 1, 0x11},
	{/* 0x1048 */ 0, 0, 0, 1, 0x12},
	{/* 0x104c */ 0, 0, 0, 1, 0x13},
	{/* 0x1050 */ 0, 0, 0, 1, 0x14},
	{/* 0x1054 */ 0, 0, 0, 1, 0x15},
	{/* 0x1058 */ 1, 0, 0, 0, 0x16},
	{/* 0x105c */ 1, 0, 0, 0, 0x17},
	{/* 0x1060 */ 0, 0, 0, 1, 0x18},
	{/* 0x1064 */ 1, 0, 0, 0, 0x19},
	{/* 0x1068 */ 0, 0, 1, 1, 0x1A},
	{/* 0x106c */ 0, 0, 1, 0, 0x1B},
	{/* 0x1070 */ 0, 0, 1, 1, 0x1C},
	{/* 0x1074 */ 0, 0, 1, 1, 0x1D},
	{/* 0x1078 */ 0, 0, 1, 1, 0x1E},
	{/* 0x107c */ 0, 0, 1, 1, 0x1F},
	{/* 0x1080 */ 1, 0, 0, 0, 0x20},
	{/* 0x1084 */ 1, 0, 0, 0, 0x21},
	{/* 0x1088 */ 1, 0, 0, 0, 0x22},
	{/* 0x108c */ 1, 0, 0, 0, 0x23},
	{/* 0x1090 */ 1, 0, 0, 0, 0x24},
	{/* 0x1094 */ 1, 0, 0, 0, 0x25},
	{/* 0x1098 */ 1, 0, 0, 0, 0x26},
	{/* 0x109c */ 1, 0, 0, 0, 0x27},
	{/* 0x10a0 */ 1, 0, 0, 0, 0x28},
	{/* 0x10a4 */ 1, 0, 0, 0, 0x29},
	{/* 0x10a8 */ 0, 1, 0, 0, 0x2A},
	{/* 0x10ac */ 0, 1, 0, 0, 0x2B},
	{/* 0x10b0 */ 1, 0, 0, 0, 0x2C},
	{/* 0x10b4 */ 0, 1, 0, 0, 0x2D},
	{/* 0x10b8 */ 0, 1, 0, 0, 0x2E},
	{/* 0x10bc */ 1, 0, 0, 0, 0x2F},
	{/* 0x10c0 */ 0, 0, 1, 1, 0x30},
	{/* 0x10c4 */ 0, 0, 1, 1, 0x31},
	{/* 0x10c8 */ 0, 0, 1, 1, 0x32},
	{/* 0x10cc */ 0, 0, 1, 1, 0x33},
	{/* 0x10d0 */ 0, 0, 1, 1, 0x34},
	{/* 0x10d4 */ 0, 0, 1, 1, 0x35},
	{/* 0X10d8 */ 0, 0, 1, 1, 0x36},
	{/* 0x10dc */ 1, 0, 0, 0, 0x37},
	{/* 0x10e0 */ 0, 0, 1, 1, 0x38},
	{/* 0x10e4 */ 0, 0, 1, 1, 0x39},
	{/* 0x10e8 */ 0, 0, 1, 1, 0x3A},
	{/* 0x10ec */ 0, 0, 1, 1, 0x3B},
	{/* 0x10f0 */ 0, 0, 1, 1, 0x3C},
	{/* 0x10f4 */ 0, 0, 1, 1, 0x3D},
	{/* 0x10f8 */ 0, 0, 1, 1, 0x3E},
	{/* 0x10fc */ 0, 0, 1, 1, 0x3F},
	{/* 0x1100 */ 0, 0, 1, 1, 0x40},
	{/* 0x1104 */ 1, 0, 0, 0, 0x41},
	{/* 0x1108 */ 1, 0, 0, 0, 0x42},
	{/* 0x110c */ 1, 0, 0, 0, 0x43},
	{/* 0x1110 */ 0, 0, 0, 0, 0x44},
	{/* 0x1114 */ 1, 0, 0, 0, 0x45},
	{/* 0x1118 */ 0, 0, 0, 1, 0x46},
	{/* 0x111c */ 1, 0, 0, 0, 0x47},
	{/* 0x1120 */ 1, 0, 0, 0, 0x48},
	{/* 0x1124 */ 1, 0, 0, 0, 0x49},
	{/* 0x1128 */ 0, 0, 1, 0, 0x4a},
	{/* 0x112c */ 0, 0, 1, 0, 0x4b},
	{/* 0x1130 */ 1, 0, 0, 0, 0x4c},
	{/* 0x1134 */ 1, 0, 0, 0, 0x4d},
	{/* 0x1138 */ 1, 0, 0, 0, 0x4e},
	{/* 0x113c */ 1, 0, 0, 0, 0x4f},
	{/* 0x1140 */ 1, 0, 0, 0, 0x50},
	{/* 0x1144 */ 1, 0, 0, 0, 0x51},
	{/* 0x1148 */ 1, 0, 0, 0, 0x52},
	{/* 0x114c */ 1, 0, 0, 0, 0x53},
	{/* 0x1150 */ 1, 0, 0, 0, 0x54},
	{/* 0x1154 */ 0, 0, 1, 1, 0x55},
	{/* 0x1158 */ 0, 0, 0, 1, 0x56},
	{/* 0x115c */ 0, 0, 1, 1, 0x57},
	{/* 0x1160 */ 1, 0, 0, 0, 0x58},
	{/* 0x1164 */ 0, 0, 0, 1, 0x59},
	{/* 0x1168 */ 0, 0, 0, 1, 0x5a},
	{/* 0x116c */ 0, 0, 1, 1, 0x5b},
	{/* 0x1170 */ 0, 0, 0, 1, 0x5c},
	{/* 0x1174 */ 1, 0, 0, 0, 0x5d},
	{/* 0x1178 */ 1, 0, 0, 0, 0x5e},
	{/* 0x117c */ 1, 0, 0, 0, 0x5f},
	{/* 0x1180 */ 0, 0, 1, 1, 0x60},
	{/* 0x1184 */ 0, 0, 1, 1, 0x61},
	{/* 0x1188 */ 0, 0, 1, 1, 0x62},
	{/* 0x118c */ 0, 0, 1, 1, 0x63},
	{/* 0x1190 */ 0, 0, 1, 1, 0x64},
	{/* 0x1194 */ 0, 0, 1, 1, 0x65},
	{/* 0x1198 */ 0, 0, 1, 1, 0x66},
	{/* 0x119c */ 0, 0, 1, 1, 0x67},
	{/* 0x11a0 */ 0, 0, 1, 1, 0x68},
	{/* 0x11a4 */ 0, 0, 1, 1, 0x69},
	{/* 0x11a8 */ 0, 0, 1, 1, 0x6A},
	{/* 0x11ac */ 0, 0, 1, 1, 0x6B},
	{/* 0x11b0 */ 0, 0, 1, 1, 0x6C},
	{/* 0x11b4 */ 0, 0, 1, 1, 0x6D},
	{/* 0x11b8 */ 0, 0, 1, 1, 0x6E},
	{/* 0x11bc */ 0, 0, 1, 1, 0x6F},
	{/* 0x11c0 */ 0, 0, 1, 1, 0x70},
	{/* 0x11c4 */ 0, 0, 1, 1, 0x71},
	{/* 0x11c8 */ 1, 0, 0, 0, 0x72},
	{/* 0x11cc */ 1, 0, 0, 0, 0x73},
	{/* 0x11d0 */ 1, 0, 0, 0, 0x74},
	{/* 0x11d4 */ 1, 0, 0, 0, 0x75},
	{/* 0x11d8 */ 0, 0, 1, 1, 0x76},
	{/* 0x11dc */ 0, 0, 0, 1, 0x77},
	{/* 0x11e0 */ 1, 0, 0, 0, 0x78},
	{/* 0x11e4 */ 0, 0, 0, 1, 0x79},
	{/* 0x11e8 */ 0, 0, 0, 1, 0x7a},
	{/* 0x11ec */ 1, 0, 0, 0, 0x7b},
	{/* 0x11f0 */ 1, 0, 0, 0, 0x7c},
	{/* 0x11f4 */ 1, 0, 0, 0, 0x7d},
	{/* 0x11f8 */ 1, 0, 0, 0, 0x7e},
	{/* 0x11fc */ 1, 0, 0, 0, 0x7f},

	{/* 0x1200 */ 1, 0, 0, 0, 0x80},
	{/* 0x1204 */ 1, 0, 0, 0, 0x81},
	{/* 0x1208 */ 1, 0, 0, 0, 0x82},
	{/* 0x120c */ 0, 0, 0, 1, 0x83},
	{/* 0x1210 */ 0, 0, 0, 1, 0x84},
	{/* 0x1214 */ 0, 0, 0, 1, 0x85},
	{/* 0x1218 */ 0, 0, 0, 1, 0x86},
	{/* 0x121c */ 1, 0, 0, 0, 0x87},
	{/* 0x1220 */ 1, 0, 0, 0, 0x88},
	{/* 0x1224 */ 1, 0, 0, 0, 0x89},
	{/* 0x1228 */ 1, 0, 0, 0, 0x8A},
	{/* 0x122c */ 1, 0, 0, 0, 0x8B},
	{/* 0x1230 */ 1, 0, 0, 0, 0x8C},
	{/* 0x1234 */ 1, 0, 0, 0, 0x8D},
	{/* 0x1238 */ 1, 0, 0, 0, 0x8E},
	{/* 0x123c */ 1, 0, 0, 0, 0x8F},
	{/* 0x1240 */ 0, 0, 1, 1, 0x90},
	{/* 0x1244 */ 0, 0, 1, 1, 0x91},
	{/* 0x1248 */ 0, 0, 1, 1, 0x92},
	{/* 0x124c */ 0, 0, 0, 1, 0x93},
	{/* 0x1250 */ 0, 0, 0, 1, 0x94},
	{/* 0x1254 */ 1, 0, 0, 0, 0x95},
	{/* 0x1258 */ 1, 0, 0, 0, 0x96},
	{/* 0x125c */ 1, 0, 0, 0, 0x97},
	{/* 0x1260 */ 1, 0, 0, 0, 0x98},
	{/* 0x1264 */ 1, 0, 0, 0, 0x99},
	{/* 0x1268 */ 1, 0, 0, 0, 0x9a},
	{/* 0x126c */ 1, 0, 0, 0, 0x9b},
	{/* 0x1270 */ 1, 0, 0, 0, 0x9c},
	{/* 0x1274 */ 1, 0, 0, 0, 0x9d},
	{/* 0x1278 */ 1, 0, 0, 0, 0x9e},
	{/* 0x127c */ 1, 0, 0, 0, 0x9f},
	{/* 0x1280 */ 1, 0, 0, 0, 0xa0},
	{/* 0x1284 */ 1, 0, 0, 0, 0xa1},
	{/* 0x1288 */ 0, 0, 0, 1, 0xa2},
	{/* 0x128c */ 0, 0, 0, 1, 0xa3},
	{/* 0x1290 */ 0, 0, 0, 1, 0xa4},
	{/* 0x1294 */ 0, 1, 0, 0, 0xa5},
	{/* 0x1298 */ 1, 0, 0, 0, 0xa6},
	{/* 0x129c */ 1, 0, 0, 0, 0xa7},
	{/* 0x12a0 */ 1, 0, 0, 0, 0xa8},
	{/* 0x12a4 */ 1, 0, 0, 0, 0xa9},
	{/* 0x12a8 */ 1, 0, 0, 0, 0xaa},
	{/* 0x12ac */ 1, 0, 0, 0, 0xab},
	{/* 0x12b0 */ 1, 0, 0, 0, 0xac},
	{/* 0x12b4 */ 1, 0, 0, 0, 0xad},
	{/* 0x12b8 */ 1, 0, 0, 0, 0xae},
	{/* 0x12bc */ 1, 0, 0, 0, 0xaf},
	{/* 0x12c0 */ 1, 0, 0, 0, 0xb0},
	{/* 0x12c4 */ 1, 0, 0, 0, 0xb1},
	{/* 0x12c8 */ 1, 0, 0, 0, 0xb2},
	{/* 0x12cc */ 1, 0, 0, 0, 0xb3},
	{/* 0x12d0 */ 1, 0, 0, 0, 0xb4},
	{/* 0x12d4 */ 1, 0, 0, 0, 0xb5},
	{/* 0X12d8 */ 1, 0, 0, 0, 0xb6},
	{/* 0x12dc */ 1, 0, 0, 0, 0xb7},
	{/* 0x12e0 */ 1, 0, 0, 0, 0xb8},
	{/* 0x12e4 */ 1, 0, 0, 0, 0xb9},
	{/* 0x12e8 */ 1, 0, 0, 0, 0xba},
	{/* 0x12ec */ 1, 0, 0, 0, 0xbb},
	{/* 0x12f0 */ 1, 0, 0, 0, 0xbc},
	{/* 0x12f4 */ 1, 0, 0, 0, 0xbd},
	{/* 0x12f8 */ 1, 0, 0, 0, 0xbe},
	{/* 0x12fc */ 1, 0, 0, 0, 0xbf},
	{/* 0x1300 */ 1, 0, 0, 0, 0xb0},
	{/* 0x1304 */ 1, 0, 0, 0, 0xc1},
	{/* 0x1308 */ 1, 0, 0, 0, 0xc2},
	{/* 0x130c */ 1, 0, 0, 0, 0xc3},
	{/* 0x1310 */ 1, 0, 0, 0, 0xc4},
	{/* 0x1314 */ 1, 0, 0, 0, 0xc5},
	{/* 0x1318 */ 1, 0, 0, 0, 0xc6},
	{/* 0x131c */ 1, 0, 0, 0, 0xc7},
	{/* 0x1320 */ 1, 0, 0, 0, 0xc8},
	{/* 0x1324 */ 1, 0, 0, 0, 0xc9},
	{/* 0x1328 */ 1, 0, 0, 0, 0xca},
	{/* 0x132c */ 1, 0, 0, 0, 0xcb},
	{/* 0x1330 */ 1, 0, 0, 0, 0xcc},
	{/* 0x1334 */ 1, 0, 0, 0, 0xcd},
	{/* 0x1338 */ 1, 0, 0, 0, 0xce},
	{/* 0x133c */ 1, 0, 0, 0, 0xcf},
	{/* 0x1340 */ 1, 0, 0, 0, 0xd0},
	{/* 0x1344 */ 1, 0, 0, 0, 0xd1},
	{/* 0x1348 */ 1, 0, 0, 0, 0xd2},
	{/* 0x134c */ 1, 0, 0, 0, 0xd3},
	{/* 0x1350 */ 1, 0, 0, 0, 0xd4},
	{/* 0x1354 */ 1, 0, 0, 0, 0xd5},
	{/* 0x1358 */ 1, 0, 0, 0, 0xd6},
	{/* 0x135c */ 1, 0, 0, 0, 0xd7},
	{/* 0x1360 */ 1, 0, 0, 0, 0xd8},
	{/* 0x1364 */ 1, 0, 0, 0, 0xd9},
	{/* 0x1368 */ 1, 0, 0, 0, 0xda},
	{/* 0x136c */ 1, 0, 0, 0, 0xdb},
	{/* 0x1370 */ 1, 0, 0, 0, 0xdc},
	{/* 0x1374 */ 1, 0, 0, 0, 0xdd},
	{/* 0x1378 */ 1, 0, 0, 0, 0xde},
	{/* 0x137c */ 1, 0, 0, 0, 0xdf},
	{/* 0x1380 */ 1, 0, 0, 0, 0xe0},
	{/* 0x1384 */ 1, 0, 0, 0, 0xe1},
	{/* 0x1388 */ 1, 0, 0, 0, 0xe2},
	{/* 0x138c */ 1, 0, 0, 0, 0xe3},
	{/* 0x1390 */ 1, 0, 0, 0, 0xe4},
	{/* 0x1394 */ 1, 0, 0, 0, 0xe5},
	{/* 0x1398 */ 1, 0, 0, 0, 0xe6},
	{/* 0x139c */ 1, 0, 0, 0, 0xe7},
	{/* 0x13a0 */ 1, 0, 0, 0, 0xe8},
	{/* 0x13a4 */ 1, 0, 0, 0, 0xe9},
	{/* 0x13a8 */ 1, 0, 0, 0, 0xea},
	{/* 0x13ac */ 1, 0, 0, 0, 0xeb},
	{/* 0x13b0 */ 1, 0, 0, 0, 0xec},
	{/* 0x13b4 */ 1, 0, 0, 0, 0xed},
	{/* 0x13b8 */ 1, 0, 0, 0, 0xee},
	{/* 0x13bc */ 1, 0, 0, 0, 0xef},
	{/* 0x13c0 */ 0, 0, 0, 1, 0xf0},
	{/* 0x13c4 */ 0, 0, 0, 1, 0xf1},
	{/* 0x13c8 */ 1, 0, 0, 0, 0xf2},
	{/* 0x13cc */ 1, 0, 0, 0, 0xf3},
	{/* 0x13d0 */ 1, 0, 0, 0, 0xf4},
	{/* 0x13d4 */ 1, 0, 0, 0, 0xf5},
	{/* 0x13d8 */ 1, 0, 0, 0, 0xf6},
	{/* 0x13dc */ 1, 0, 0, 0, 0xf7},
	{/* 0x13e0 */ 1, 0, 0, 0, 0xf8},
	{/* 0x13e4 */ 1, 0, 0, 0, 0xf9},
	{/* 0x13e8 */ 1, 0, 0, 0, 0xfa},
	{/* 0x13ec */ 1, 0, 0, 0, 0xfb},
	{/* 0x13f0 */ 1, 0, 0, 0, 0xfc},
	{/* 0x13f4 */ 1, 0, 0, 0, 0xfd},
	{/* 0x13f8 */ 1, 0, 0, 0, 0xfe},
	{/* 0x13fc */ 1, 0, 0, 0, 0xff},
};

static void grc_global_qos_default_cfg(struct nbl_grc *grc)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;

	grc_wr32(

		grc_to_hw_addr(grc),
		NBL_DSCH_REG_ADDR(regs->dsch_base, NBL_DSCH_IMAP_CFG_OFF_V2),
		NBL_QOS_DEFAULT_PRI_IMAP
	);
	grc_wr32(
		grc_to_hw_addr(grc),
		NBL_DSCH_REG_ADDR(regs->dsch_base, NBL_DSCH_SQ_PRI_MAP_CFG_OFF_V2),
		NBL_QOS_DEFAULT_SQ_PRI_MAP
	);
	grc_wr32(
		grc_to_hw_addr(grc),
		NBL_DSCH_REG_ADDR(regs->dsch_base, NBL_DSCH_RAQ_PRI_MAP_CFG_OFF_V2),
		NBL_QOS_DEFAULT_RAQ_PRI_MAP
	);
	grc_wr32(
		grc_to_hw_addr(grc),
		NBL_DSCH_REG_ADDR(regs->dsch_base, NBL_DSCH_PRI03_MAP_CFG_OFF_V2),
		NBL_QOS_DEFAULT_PFC03_MAP
	);
	grc_wr32(
		grc_to_hw_addr(grc),
		NBL_DSCH_REG_ADDR(regs->dsch_base, NBL_DSCH_PRI47_MAP_CFG_OFF_V2),
		NBL_QOS_DEFAULT_PFC47_MAP
	);
	grc_wr32(
		grc_to_hw_addr(grc),
		NBL_DSCH_REG_ADDR(regs->dsch_base, NBL_DSCH_SW_DB_IN_CSCH_TH_OFF_V2),
		NBL_QOS_DEFAULT_SW_DB_IN_CSCH_TH
	);
	grc_wr32(
		grc_to_hw_addr(grc),
		NBL_DSCH_REG_ADDR(regs->dsch_base, NBL_DSCH_CSCH_QLEN_TH_OFF_V2),
		NBL_QOS_DEFAULT_CSCH_QLEN_TH
	);
	grc_wr32(
		grc_to_hw_addr(grc),
		NBL_DSCH_REG_ADDR(regs->dsch_base, NBL_DSCH_DB_TO_CSCH_EN_OFF_V2),
		NBL_QOS_DEFAULT_DB_TOCSCH_EN
	);
}

static void grc_set_sd_range(struct nbl_grc *grc,
			     u16 function_id, u32 sd_start, u32 sd_cnt, bool valid)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	struct nbl_core_export *core_dev = &grc->core_dev;
	union nbl_sd_range_tbl_reg sd_range_tbl = {};
	u64 reg_addr;
	u32 *value;
	u32 sd_range;

	reg_addr = NBL_CQPP_SDBASE_TBL_ADDR(regs->cqpp_base, function_id);

	if (valid) {
		sd_range_tbl.sd_base_idx = sd_start;
		sd_range_tbl.sd_max_num = sd_cnt;
		value = (u32 *)&sd_range_tbl;
		sd_range_tbl.sd_base_info_vld = valid;
	} else {
		sd_range = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);
		sd_range &= ~((u32)BIT(31));
		value = &sd_range;
	}

	grc_wr32(grc_to_hw_addr(grc), reg_addr, *value);
}

static void __grc_get_sd_range(struct nbl_grc *grc, u16 function_id,
			       u32 *sd_start, u32 *sd_cnt)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	struct nbl_core_export *core_dev = &grc->core_dev;
	union nbl_sd_range_tbl_reg sd_range_tbl = {};
	void *reg_addr;
	u32 *value = (u32 *)&sd_range_tbl;

	reg_addr = core_dev->hw_addr +
		   NBL_CQPP_SDBASE_TBL_ADDR(regs->cqpp_base, function_id);
	*value = readl(reg_addr);

	*sd_start = sd_range_tbl.sd_base_idx;
	*sd_cnt = sd_range_tbl.sd_max_num;
	grc_pr_debug("got sd_range_tbl(start=%u,cnt=%u,vld=%u) for func_id=%u\n",
		     *sd_start, *sd_cnt, sd_range_tbl.sd_base_info_vld, function_id);
}

static void grc_set_bdf_func_id_map(struct nbl_grc *grc, bool host_en,
				    u32 bdf_num, u16 func_id)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	union nbl_hdma_bdf_tbl_reg bdf_tbl = {};
	u64 reg_addr;
	u32 *value;

	grc_pr_debug("set bdf_tbl reg for func_id=%u,host_en=%u,bdf_num=0x%x\n",
		     func_id, host_en, bdf_num);

	memcpy(bdf_tbl.data, &bdf_num, sizeof(union nbl_hdma_bdf_tbl_reg));
	bdf_tbl.key.host_en = host_en;

	grc_pr_debug("set bdf_tbl bus=%u,dev=%u,func=%u,func_id=%u,host_en=%u\n",
		     bdf_tbl.key.bus_id, bdf_tbl.key.device_id,
		     bdf_tbl.key.function_id, func_id, bdf_tbl.key.host_en);

	value = (u32 *)&bdf_tbl;

	reg_addr = NBL_HDMA_BDF_TBL_ADDR(regs->hdma_base, func_id);
	grc_wr32(grc_to_hw_addr(grc), reg_addr, *value);
}

static void grc_set_pf_tbl(struct nbl_grc *grc, u16 function_id, u16 pf_id)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	u64 reg_addr;
	union nbl_hdma_pf_tbl_reg pf_tbl = {};

	pf_tbl.key.bdf_tbl_idx = pf_id;
	reg_addr = NBL_HDMA_PF_TBL_ADDR(regs->hdma_base, function_id);
	grc_pr_notice("func_id:%d pf_id:%d reg:%#llx\n", function_id, pf_id,
		      reg_addr);
	grc_wr32(grc_to_hw_addr(grc), reg_addr, pf_tbl.data[0]);
}

static struct grc_dsch_spec dsch_id_spec = {
	.min_net_shaping_id = NBL_GRC_MIN_NET_SHAPING_ID,
	.max_net_shaping_id = NBL_GRC_MAX_NET_SHAPING_ID,
};

static struct grc_dsch_spec *grc_get_dsch_spec(void)
{
	return &dsch_id_spec;
}

static void grc_set_rdma_net_en(struct nbl_grc *grc, u16 function_id)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	struct nbl_core_export *core_dev = &grc->core_dev;
	u64 reg_addr;
	u32 rdma_net_en_val = 0;
	u32 index = function_id % NBL_DSCH_NET_EN_REG_BITS;

	reg_addr = NBL_DSCH_REG_ADDR(regs->dsch_base,
				     NBL_DSCH_NET_EN_OFF_V2) +
		   4 * (function_id / NBL_DSCH_NET_EN_REG_BITS);
	rdma_net_en_val = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);
	rdma_net_en_val |= ((u32)1 << index);
	grc_wr32(grc_to_hw_addr(grc), reg_addr, rdma_net_en_val);
}

static void grc_clear_rdma_net_en(struct nbl_grc *grc, u16 function_id)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	struct nbl_core_export *core_dev = &grc->core_dev;
	u64 reg_addr;
	u32 rdma_net_en_val = 0;
	u32 index = function_id % NBL_DSCH_NET_EN_REG_BITS;

	reg_addr = NBL_DSCH_REG_ADDR(regs->dsch_base,
				     NBL_DSCH_NET_EN_OFF_V2) +
		   4 * (function_id / NBL_DSCH_NET_EN_REG_BITS);
	rdma_net_en_val = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);
	rdma_net_en_val &= ~((u32)1 << index);
	grc_wr32(grc_to_hw_addr(grc), reg_addr, rdma_net_en_val);
}

static bool grc_check_netnode_if_flush(struct nbl_grc *grc, u16 function_id)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	struct nbl_core_export *core_dev = &grc->core_dev;
	u64 reg_addr;
	bool rdma_tc_q_flush = true;
	bool rdma_dbq_flush = true;
	u16 net_tc;
	u32 attr_val;
	union rdma_tc_q_list_attr_tbl tc_q_list = {};

	reg_addr = NBL_DSCH_DBQ_ATTR_TBL_ADDR(regs->dsch_base, function_id);
	for (net_tc = 0; net_tc < NBL_DSCH_TC_NUM; net_tc++) {
		attr_val = grc_rd32(grc_cdev_to_hw_addr(core_dev),
				    reg_addr + net_tc * NBL_DSCH_DBQ_ATTR_TC_STRIDE);
		if (attr_val & NBL_DSCH_DBQ_ATTR_TBL_NEMPTY) {
			rdma_dbq_flush = false;
			break;
		}
	}

	reg_addr = NBL_DSCH_TC_Q_LIST_ATTR_TBL_ADDR(regs->dsch_base, function_id);
	for (net_tc = 0; net_tc < NBL_DSCH_TC_NUM; net_tc++) {
		tc_q_list.data[0] = grc_rd32(grc_cdev_to_hw_addr(core_dev),
					     reg_addr + net_tc * NBL_DSCH_TC_Q_LIST_ATTR_TC_STRIDE);
		if (tc_q_list.fly || tc_q_list.rlen || tc_q_list.wlen) {
			rdma_tc_q_flush = false;
			break;
		}
	}

	if (!rdma_tc_q_flush || !rdma_dbq_flush) {
		dev_warn(&core_dev->pdev->dev, "func=%u,rdma_tc_q_flush=%u,rdma_dbq_flush=%u\n",
			 function_id, rdma_tc_q_flush, rdma_dbq_flush);
		return false;
	}

	return true;
}

static bool grc_check_netnode_is_init(struct nbl_grc *grc, u16 net_id)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	struct nbl_core_export *core_dev = &grc->core_dev;
	u64 reg_addr;
	union rdma_grp_net_list_tbl_v2 net_list_tbl = {};

	reg_addr = NBL_DSCH_GRP_NET_LIST_TBL_ADDR(regs->dsch_base, net_id);
	net_list_tbl.data[0] = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);
	if (net_list_tbl.valid || net_list_tbl.pfc || net_list_tbl.sst)
		return false;

	return true;
}

static bool grc_grp_node_if_need_disable(struct nbl_grc *grc, u16 grp_id)
{
	spin_lock(&grc->grp_list_lock);
	if (grc->grp_list[grp_id].count) {
		spin_unlock(&grc->grp_list_lock);
		return false;
	}

	spin_unlock(&grc->grp_list_lock);
	return true;
}

static bool grc_check_grpnode_is_init(struct nbl_grc *grc, u16 grp_id)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	struct nbl_core_export *core_dev = &grc->core_dev;
	u64 reg_addr;
	union rdma_spt_grp_list_tbl_v2 grp_list_tbl = {};

	reg_addr = NBL_DSCH_SPT_GRP_LIST_TBL_ADDR(regs->dsch_base, grp_id);
	grp_list_tbl.data[0] = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);
	if (grp_list_tbl.valid || grp_list_tbl.sst)
		return false;

	return true;
}

static void grc_disable_rdma_net(struct nbl_grc *grc, u16 function_id, uint8_t vld)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	struct nbl_core_export *core_dev = &grc->core_dev;
	u64 reg_addr;
	union rdma_n2g_cfg_tbl n2g_map = {};
	u32 *value;
	bool net_flush_comp = false;
	bool net_init_state = false;
	bool need_check_flush = true;
	bool need_check_init = true;
	u16 grp_id;
	bool grp_flag = false;
	u16 retry_count = 0;

	/* 1) disable rdma_net_en */
	grc_clear_rdma_net_en(grc, function_id);

	do {
		if (need_check_flush) {
			net_flush_comp = grc_check_netnode_if_flush(grc, function_id);
			if (net_flush_comp)
				need_check_flush = false;
		}

		if (need_check_init) {
			net_init_state = grc_check_netnode_is_init(grc, function_id);
			if (net_init_state)
				need_check_init = false;
		}

		if (net_flush_comp && net_init_state)
			break;

		dev_warn_ratelimited(&core_dev->pdev->dev, "rdma%u node not back to init\n"
				     "(flush_comp=%u,init_state=%u),waiting..\n",
				     function_id, net_flush_comp, net_init_state);
		retry_count++;
		mdelay(DSCH_RDMA_DISABLE_DELAY_TIME);
	} while (retry_count < DSCH_RDMA_MAX_RETRY_COUNT);

	grc_pr_debug("clear n2g config for function=%u", function_id);
	/* 2) disable net2grp */
	reg_addr = NBL_DSCH_N2G_CFG_TBL_ADDR(regs->dsch_base, function_id);
	value = (u32 *)&n2g_map;
	*value = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);
	grp_id = n2g_map.grp_id;

	memset(&n2g_map, 0, sizeof(n2g_map));
	grc_wr32(grc_to_hw_addr(grc), reg_addr, *value);

	spin_lock(&grc->grp_list_lock);
	clear_bit(function_id, grc->grp_list[grp_id].net_id_list);
	grc->grp_list[grp_id].count--;
	spin_unlock(&grc->grp_list_lock);

	grp_flag = grc_grp_node_if_need_disable(grc, grp_id);
	if (grp_flag) {
		bool grp_init_state = false;

		do {
			grp_init_state = grc_check_grpnode_is_init(grc, grp_id);
			if (!grp_init_state) {
				mdelay(DSCH_RDMA_DISABLE_DELAY_TIME);
				grc_pr_debug("rdma%u grpnode not back to init state,waiting...",
					     function_id);
				continue;
			}
			break;
		} while (1);
	}
}

static void grc_enable_dsch(struct nbl_grc *grc, u16 function_id,
			    u32 host_id, u16 dport_id, uint8_t vld)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	u64 reg_addr;
	union rdma_n2g_cfg_tbl n2g_map = {};
	union rdma_g2p_cfg_tbl_v2 g2p_map = {};
	union rdma_tc_spwrr_cfg_tbl tc_spwrr_map = {};
	union rdma_net2sha_map_tbl_v2 n2s_map = {};
	union rdma_grp2sha_map_tbl_v2 g2s_map = {};
	union rdma_sha2net_map_tbl s2n_map = {};
	union rdma_sha2grp_map_tbl s2g_map = {};
	u32 *value;
	struct grc_dsch_spec *dsch_spec = grc_get_dsch_spec();

	grc_pr_debug(
		"enable rdma dsch regs for function_id=%u,host_id=%u,dport=%u,vld=%u\n",
		function_id, host_id, dport_id, vld);

	/* 1) enable grp2port */
	reg_addr = NBL_DSCH_G2P_CFG_TBL_ADDR(regs->dsch_base, function_id);
	g2p_map.vld = vld;
	g2p_map.port = dport_id;
	value = (u32 *)&g2p_map;
	grc_wr32(grc_to_hw_addr(grc), reg_addr, *value);

	/* 2) enable net2grp */
	reg_addr = NBL_DSCH_N2G_CFG_TBL_ADDR(regs->dsch_base, function_id);
	n2g_map.vld = vld;
	n2g_map.grp_id = function_id;
	value = (u32 *)&n2g_map;
	grc_wr32(grc_to_hw_addr(grc), reg_addr, *value);

	/* 3) enable rdma_net_en */
	spin_lock(&grc->grp_list_lock);
	set_bit(function_id, grc->grp_list[function_id].net_id_list);
	grc->grp_list[function_id].count++;
	spin_unlock(&grc->grp_list_lock);
	grc_set_rdma_net_en(grc, function_id);

	reg_addr = NBL_DSCH_TC_SPWRR_CFG_TBL_ADDR(regs->dsch_base, function_id);
	tc_spwrr_map.tc_spwrr = nbl_tm_algorithm_dwrr;
	value = (u32 *)&tc_spwrr_map;
	grc_wr32(grc_to_hw_addr(grc), reg_addr, *value);

	/* 4) enable sha2net,sha2grp */
	n2s_map.net_shaping_id = dsch_spec->min_net_shaping_id + function_id;
	reg_addr = NBL_DSCH_SHA2NET_MAP_TBL_ADDR(regs->dsch_base, n2s_map.net_shaping_id);
	s2n_map.vld = vld;
	s2n_map.rdma_vf_id = function_id;
	value = (u32 *)&s2n_map;
	grc_wr32(grc_to_hw_addr(grc), reg_addr, *value);

	g2s_map.grp_shaping_id = function_id;
	reg_addr = NBL_DSCH_SHA2GRP_MAP_TBL_ADDR(regs->dsch_base, g2s_map.grp_shaping_id);
	s2g_map.vld = vld;
	s2g_map.rdma_grp_id = n2g_map.grp_id;
	value = (u32 *)&s2g_map;
	grc_wr32(grc_to_hw_addr(grc), reg_addr, *value);

	/* 5) enable net2sha,grp2sha */
	reg_addr = NBL_DSCH_NET2SHA_MAP_TBL_ADDR(regs->dsch_base, function_id);
	n2s_map.vld = vld;
	n2s_map.net_shaping_id = dsch_spec->min_net_shaping_id + function_id;
	value = (u32 *)&n2s_map;
	grc_wr32(grc_to_hw_addr(grc), reg_addr, *value);

	reg_addr = NBL_DSCH_GRP2SHA_MAP_TBL_ADDR(regs->dsch_base, function_id);
	g2s_map.vld = vld;
	g2s_map.grp_shaping_id = function_id;
	value = (u32 *)&g2s_map;
	grc_wr32(grc_to_hw_addr(grc), reg_addr, *value);
}

static void grc_disable_dsch(struct nbl_grc *grc,
			     u16 function_id, u32 host_id, u16 dport_id,
			     uint8_t vld)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	struct nbl_core_export *core_dev = &grc->core_dev;
	u64 reg_addr;
	union rdma_n2g_cfg_tbl n2g_map = {};
	union rdma_g2p_cfg_tbl_v2 g2p_map = {};
	union rdma_tc_wgt_cfg_tbl tc_wgt_map = {};
	union rdma_tc_spwrr_cfg_tbl tc_spwrr_map = {};
	union rdma_net2sha_map_tbl_v2 n2s_map = {};
	union rdma_grp2sha_map_tbl_v2 g2s_map = {};
	union rdma_sha2net_map_tbl s2n_map = {};
	union rdma_sha2grp_map_tbl s2g_map = {};
	u32 *value;
	bool grp_flag;

	grc_pr_debug(
		"disable rdma dsch regs for function_id=%u,host_id=%u,dport=%u,vld=%u\n",
		function_id, host_id, dport_id, vld);

	/* save n2p cfg before grc_disable_rdma_net */
	reg_addr = NBL_DSCH_N2G_CFG_TBL_ADDR(regs->dsch_base, function_id);
	value = (u32 *)&n2g_map;
	*value = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);

	grc_disable_rdma_net(grc, function_id, vld);

	reg_addr = NBL_DSCH_TC_WGT_CFG_TBL_ADDR(regs->dsch_base, function_id);
	value = &tc_wgt_map.data[0];
	grc_wr32(grc_to_hw_addr(grc), reg_addr, *value);
	value = &tc_wgt_map.data[1];
	grc_wr32(grc_to_hw_addr(grc), reg_addr, *value);

	reg_addr = NBL_DSCH_TC_SPWRR_CFG_TBL_ADDR(regs->dsch_base, function_id);
	tc_spwrr_map.tc_spwrr = nbl_tm_algorithm_dwrr;
	value = (u32 *)&tc_spwrr_map;
	grc_wr32(grc_to_hw_addr(grc), reg_addr, *value);

	/* 3) disable sha2net */
	reg_addr = NBL_DSCH_NET2SHA_MAP_TBL_ADDR(regs->dsch_base, function_id);
	value = (u32 *)&n2s_map;
	*value = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);

	reg_addr = NBL_DSCH_SHA2NET_MAP_TBL_ADDR(regs->dsch_base, n2s_map.net_shaping_id);
	value = (u32 *)&s2n_map;
	grc_wr32(grc_to_hw_addr(grc), reg_addr, *value);

	/* 4) disable net2sha */
	reg_addr = NBL_DSCH_NET2SHA_MAP_TBL_ADDR(regs->dsch_base, function_id);
	memset(&n2s_map, 0, sizeof(n2s_map));
	value = (u32 *)&n2s_map;
	grc_wr32(grc_to_hw_addr(grc), reg_addr, *value);

	/* 5) disable grp2port */
	reg_addr = NBL_DSCH_G2P_CFG_TBL_ADDR(regs->dsch_base, n2g_map.grp_id);
	value = (u32 *)&g2p_map;
	grc_wr32(grc_to_hw_addr(grc), reg_addr, *value);

	/* 6) disable sha2grp */
	reg_addr = NBL_DSCH_GRP2SHA_MAP_TBL_ADDR(regs->dsch_base, n2g_map.grp_id);
	value = (u32 *)&g2s_map;
	*value = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);

	reg_addr = NBL_DSCH_SHA2GRP_MAP_TBL_ADDR(regs->dsch_base, g2s_map.grp_shaping_id);
	value = (u32 *)&s2g_map;
	grp_flag = grc_grp_node_if_need_disable(grc, n2g_map.grp_id);
	if (!vld && grp_flag)
		grc_wr32(grc_to_hw_addr(grc), reg_addr, *value);

	/* 7) disable grp2sha */
	reg_addr = NBL_DSCH_GRP2SHA_MAP_TBL_ADDR(regs->dsch_base, n2g_map.grp_id);
	memset(&g2s_map, 0, sizeof(g2s_map));
	value = (u32 *)&g2s_map;
	grp_flag = grc_grp_node_if_need_disable(grc, n2g_map.grp_id);
	if (!vld && grp_flag)
		grc_wr32(grc_to_hw_addr(grc), reg_addr, *value);
}

static void grc_set_dsch_tbl(struct nbl_grc *grc,
			     u16 function_id, u32 host_id, u16 dport_id, u8 vld)
{
	if (vld)
		grc_enable_dsch(grc, function_id, host_id, dport_id, vld);
	else
		grc_disable_dsch(grc, function_id, host_id, dport_id, vld);

	grc_pr_debug("setting dsch regs end function_id=%u,host_id=%u,valid=%u\n",
		     function_id, host_id, vld);
}

static void nbl_update_rdma_dsch(struct nbl_grc *grc, u16 function_id,
				 u32 host_id, u16 dport_id, u8 vld)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	u64 reg_addr;
	union rdma_g2p_cfg_tbl_v2 g2p_map = {};
	u32 *value;

	reg_addr = NBL_DSCH_G2P_CFG_TBL_ADDR(regs->dsch_base, function_id);
	g2p_map.vld = vld;
	g2p_map.port = dport_id;
	value = (u32 *)&g2p_map;
	grc_wr32(grc_to_hw_addr(grc), reg_addr, *value);
}

static void grc_set_cqp_info(struct nbl_grc *grc, u16 function_id,
			     u64 cqp_ba, u32 cqp_len, bool enable)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	struct nbl_core_export *core_dev = &grc->core_dev;
	u64 regs_addr;
	union nbl_cqp_info_tbl_reg cqp_info_tbl_reg = {};

	grc_pr_debug("cqp_ba=0x%llx,cqp_len=%u,function_id=%u,valid=%s",
		     cqp_ba, cqp_len, function_id, enable ? "true" : "false");
	regs_addr = NBL_CQPP_CQPINFO_TBL_ADDR(regs->cqpp_base, function_id);
	if (enable) {
		cqp_info_tbl_reg.key.cqp_base_addr_high = (u32)(cqp_ba >> 32);
		cqp_info_tbl_reg.key.cqp_base_addr_low = (u32)cqp_ba;
		cqp_info_tbl_reg.key.cqp_pi_odd_even_flag = 0;
		cqp_info_tbl_reg.key.cqp_pi = 0;
		cqp_info_tbl_reg.key.cqp_info_vld = 1;
		cqp_info_tbl_reg.key.cqp_ci_odd_even_flag = 0;
		cqp_info_tbl_reg.key.cqp_ci = 0;

		/* as hardware need write valid at last, so here write cqp valid last */
		grc_write_regs(grc_to_hw_addr(grc), regs_addr,
			       cqp_info_tbl_reg.data, ARRAY_SIZE(cqp_info_tbl_reg.data));
	} else {
		grc_read_regs(grc_cdev_to_hw_addr(core_dev), regs_addr,
			      cqp_info_tbl_reg.data, ARRAY_SIZE(cqp_info_tbl_reg.data));
		cqp_info_tbl_reg.key.cqp_info_vld = 0;
		grc_write_regs(grc_to_hw_addr(grc), regs_addr,
			       cqp_info_tbl_reg.data, ARRAY_SIZE(cqp_info_tbl_reg.data));
	}
}

static void grc_set_cqp_pi(struct nbl_grc *grc, u32 cur_pi, u8 odd_even)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	struct nbl_core_export *core_dev = &grc->core_dev;
	u64 regs_addr;
	union nbl_cqp_info_tbl_reg cqp_info_tbl_reg = {};

	cqp_info_tbl_reg.key.cqp_pi = cur_pi;
	cqp_info_tbl_reg.key.cqp_pi_odd_even_flag = odd_even;
	regs_addr = NBL_CQPP_CQPINFO_TBL_ADDR(regs->cqpp_base,
					      core_dev->real_function);
	grc_wr32(grc_to_hw_addr(grc),
		 regs_addr + NBL_CQPP_CQPINFO_PI_DW_OFF,
		 cqp_info_tbl_reg.data[NBL_CQPP_CQPINFO_PI_DW_INDEX]);
	grc_pr_debug("write cqp info table reg addr 0x%llx, val 0x%x\n",
		     (regs_addr + NBL_CQPP_CQPINFO_PI_DW_OFF),
		     cqp_info_tbl_reg.data[NBL_CQPP_CQPINFO_PI_DW_INDEX]);
}

static void grc_set_src_addr_info(struct nbl_grc *grc, const u8 *smac, const u8 *sip,
				  u16 src_addr_index, u8 seq_num)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	u64 reg_addr;
	union nbl_src_addr_info_tbl_reg info_tbl_reg = {};
	u32 write_num;
	int i, j;

	/* fill src addr info tbl seg */
	/*
	 * for srcmac of key, byte0 corresponds to low-order information,
	 * and byte5 corresponds to high-order information
	 */
	for (i = 0; i < NBL_SRC_MAC_SIZE; i++)
		info_tbl_reg.key.smac[i] = smac[NBL_SRC_MAC_SIZE - 1 - i];

	/*
	 * for sip of key, byte0 corresponds to low-order information,
	 * and byte15 corresponds to high-order information
	 */
	for (j = 0; j < NBL_SRC_IP_SIZE; j++)
		info_tbl_reg.key.sip[j] = sip[NBL_SRC_IP_SIZE - 1 - j];

	info_tbl_reg.key.seq_num = (seq_num & NBL_TXM_SRC_ADDR_SEQ_NUM_MASK);

	write_num = NBL_TXM_SRC_ADDR_TBL_DW_SIZE;
	reg_addr = NBL_TXM_SRC_ADDR_TBL_ADDR(regs->txm_base,
					     src_addr_index);
	grc_pr_debug("initial reg addr[0x%llx]\n", reg_addr);

	for (i = 0; i < write_num; i++) {
		grc_wr32(grc_to_hw_addr(grc),
			reg_addr + (i * 4), info_tbl_reg.data[i]);
		grc_pr_debug(
			"write src addr info table reg addr[0x%llx], val[0x%x]\n",
			(reg_addr + (i * 4)), info_tbl_reg.data[i]);
	};
}

static void grc_set_hw_stat(struct nbl_grc *grc, u32 op_info)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	u64 reg_addr;

	reg_addr = NBL_STAT_REG_ADDR(regs->stat_base, NBL_STAT_OP_INFO_OFF);
	grc_wr32(grc_to_hw_addr(grc), reg_addr, op_info);
	grc_pr_debug("reg_addr:0x%llx, op_info:[0x%x:0x%x]\n",
		      reg_addr, (u32)reg_addr, op_info);
}

static void grc_get_hw_stat(struct nbl_grc *grc, u32 op_info,
			    u32 pa_l, u32 pa_h, u16 func_id)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	u64 op_info_addr = NBL_STAT_REG_ADDR(regs->stat_base,
					     NBL_STAT_OP_INFO_OFF);
	u64 dma_addr_l = NBL_STAT_REG_ADDR(regs->stat_base,
					   NBL_STAT_OP_DMA_ADDR_L_OFF);
	u64 dma_addr_h = NBL_STAT_REG_ADDR(regs->stat_base,
					   NBL_STAT_OP_DMA_ADDR_H_OFF);
	u64 func_id_addr = NBL_STAT_REG_ADDR(regs->stat_base,
					     NBL_STAT_FUNC_ID_OFF);

	grc_pr_debug("func_id:%d, info[0x%x:0x%x]\n", func_id,
		     (u32)op_info_addr, op_info);
	grc_pr_debug("pa_h[0x%x:0x%x], pa_l[0x%x:0x%x]\n",
		     (u32)dma_addr_h, pa_h, (u32)dma_addr_l, pa_l);

	grc_wr32(grc_to_hw_addr(grc), func_id_addr, func_id);
	grc_wr32(grc_to_hw_addr(grc), dma_addr_l, pa_l);
	grc_wr32(grc_to_hw_addr(grc), dma_addr_h, pa_h);
	grc_wr32(grc_to_hw_addr(grc), op_info_addr, op_info);
}

static void grc_enable_errcode_hw_stat(struct nbl_grc *grc,
				       u32 enable)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	u64 reg_addr = NBL_STAT_REG_ADDR(regs->stat_base,
					 NBL_STAT_OP_ERR_OPCODE_EN_OFF);

	grc_wr32(grc_to_hw_addr(grc), reg_addr, enable);
	grc_pr_debug("offset:[0x%x:0x%x]\n", (u32)reg_addr, enable);
}

static void grc_get_hw_status(struct nbl_grc *grc, u32 *status)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	struct nbl_core_export *core_dev = &grc->core_dev;
	u64 reg_offset = NBL_STAT_REG_ADDR(regs->stat_base,
					   NBL_STAT_OP_INFO_OFF);
	void *reg_addr;

	reg_addr = core_dev->hw_addr + reg_offset;
	*status = readl(reg_addr);
	grc_pr_debug("reg_addr:%p, status:[0x%x:0x%x]\n",
		     reg_addr, (u32)reg_offset, *status);
}

static void nbl_set_rdma_pfid_map_tbl(struct nbl_grc *grc, u16 idx,
				      u16 rdma_fn_id, bool valid)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	u64 reg_addr;
	union nbl_pcomp_fid_tbl_reg map = {};

	reg_addr = NBL_PCOMP_FID_TBL_ADDR(regs->pcomp_base, idx);

	map.rdma_fid = rdma_fn_id;
	map.valid = valid;
	grc_wr32(grc_to_hw_addr(grc), reg_addr, map.data);
}

static u32 nbl_ib_get_reg_offset_addr(const struct nbl_grc_register_layout *regs,
				      u32 offset)
{
	const u32 cc_base = regs->cc_base;
	const u32 txp_base = regs->txp_base;
	const u32 txm_base = regs->txm_base;

	switch (offset) {
	case NBL_CFG_CC_EN:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_EN_OFF);
	case NBL_CFG_CC_HIGH_RTT_FRACTION:
	case NBL_CFG_CC_LOW_RTT_FRACTION:
	case NBL_CFG_CC_HIGH_RTT_INT:
	case NBL_CFG_CC_LOW_RTT_INT:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_RTTMINTH_COE_OFF);
	case NBL_CFG_CC_INC_TARWINTH:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_INC_TARGET_WIN_TH_OFF);
	case NBL_CFG_CC_DEC_TARWINTH:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_DEC_TARGET_WIN_TH_OFF);
	case NBL_CFG_CC_TARGET_RTTMIN:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_TARGET_RTTMIN_OFF);
	case NBL_CFG_CC_TXP_SENDREQ_DB_CFG:
		return NBL_TXP_REG_ADDR(txp_base,
					 NBL_TXP_CC_SENDREQ_DB_CFG_OFF);
	case NBL_CFG_QCN_RR_MODE:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_RR_MODE_OFF);
	case NBL_CFG_QCN_MID_SENDBLK_TH_HIGH:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_MID_SENDBLK_TH_HIGH_OFF);
	case NBL_CFG_QCN_MID_SENDBLK_TH_LOW:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_MID_SENDBLK_TH_LOW_OFF);
	case NBL_CFG_QCN_MID_SENDTIME_TH_HIGH:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_MID_SENDTIME_TH_HIGH_OFF);
	case NBL_CFG_QCN_MID_SENDTIME_TH_LOW:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_MID_SENDTIME_TH_LOW_OFF);
	case NBL_CFG_QCN_RR_TH:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_RR_TH_OFF);
	case NBL_CFG_QCN_AI_RP:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_AI_RP_OFF);
	case NBL_CFG_QCN_HAI_RP:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_HAI_RP_OFF);
	case NBL_CFG_QCN_MIN_RATE_RP:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_MIN_RATE_RP_OFF);
	case NBL_CFG_QCN_MAX_RATE_RP:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_MAX_RATE_RP_OFF);
	case NBL_CFG_QCN_QUICK_START_FLAG:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_QUICK_START_FLAG_OFF);
	case NBL_CFG_QCN_SENDCNP_FLAG:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_SENDCNP_FLAG_OFF);
	case NBL_CFG_QCN_SENDCNP_TIME_TH:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_SENDCNP_TIME_TH_OFF);
	case NBL_CFG_QCN_EXTRA_QUANTA:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_EXTRA_QUANTA_OFF);
	case NBL_CFG_QCN_FAST_REDUCE_MODE:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_FAST_REDUCE_MODE_OFF);
	case NBL_CFG_QCN_REDUCE_COE:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_REDUCE_COE_OFF);
	case NBL_CFG_CC_RTT_OFFSET:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_RTT_OFFSET_OFF);
	case NBL_CFG_CC_RTT_PROBE_INVL:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_RTT_PROBE_INVL_OFF);
	case NBL_CFG_CC_HIGH_PRI_RTT_INVL:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_HIGH_PRI_RTT_INVL_OFF);
	case NBL_CFG_CC_HIGH_PRI_RTT_EN:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_HIGH_RPI_RTT_EN_OFF);
	case NBL_CFG_CC_RST_WIN_HIGH:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_RST_WIN_H_OFF);
	case NBL_CFG_CC_RST_WIN_EN:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_RST_WIN_EN_OFF);
	case NBL_CFG_CC_RST_WIN_LOW:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_RST_WIN_L_OFF);
	case NBL_CFG_CC_RST_WIN_RTT_INT:
	case NBL_CFG_CC_RST_WIN_RTT_FRACTION:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_RST_TARGETWIN_RTTCOE_OFF);
	case NBL_CFG_CC_DYN_RTT_OFFSET_EN:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_DYN_RTT_OFFSET_EN_OFF);
	case NBL_CFG_CC_REMOVE_REMOTE_TIME:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_REMOVE_REMOTE_TIME_OFF);
	case NBL_CFG_CC_RDMA_TIME_SEL:
		return NBL_TXM_REG_ADDR(txm_base,
					 NBL_TXM_RDMA_TIME_SEL_OFF);
	case NBL_CFG_CC_LOW_RTT_OFFSET:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_AI_LESS_RTTMINTH_OFF);
	case NBL_CFG_CC_HIGH_RTT_OFFSET:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_AI_MORE_RTTMINTH_OFF);
	case NBL_CFG_CC_RST_WIN_RTT_OFFSET:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_AI_RST_WIN_RTTMINTH_OFF);
	case NBL_CFG_CC_OAMACK_BLK_TH:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_SENDACK_BLK_CNT_TH_OFF);
	case NBL_CFG_QCN_TIME_ACCUM:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_TIME_ACCUM_OFF);
	case NBL_CFG_QCN_USE_HAI_EN:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_USE_HAI_EN_OFF);
	case NBL_CFG_QCN_QUANTA_CC2TXP:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_QUANTA_CC2TXP_OFF);
	default:
		return 0;
	}
}

static void grc_set_cc_params(struct nbl_grc *grc,
			      u32 offset, u32 var)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	struct nbl_core_export *core_dev = &grc->core_dev;
	u64 reg_addr;
	u32 offset_addr;
	u32 var_old;
	u32 tmp_addr;
	u32 tmp_offset;
	u32 tmp_var;

	offset_addr = nbl_ib_get_reg_offset_addr(regs, offset);
	if (offset_addr == 0) {
		grc_pr_err("get reg addr failed, cc param offset:%d var:%u\n", offset, var);
		return;
	}

	reg_addr = offset_addr;
	switch (offset) {
	case NBL_CFG_CC_EN:
		tmp_offset = nbl_ib_get_reg_offset_addr(regs, NBL_CFG_CC_TXP_SENDREQ_DB_CFG);
		if (tmp_offset == 0) {
			grc_pr_err("tmp_offset:%u\n", tmp_offset);
			return;
		}
		tmp_addr = tmp_offset;
		var_old = grc_rd32(grc_cdev_to_hw_addr(core_dev), tmp_addr);
		tmp_var = (var_old & 0x7FFFFFFF) | ((var << 31) & 0x80000000);
		grc_wr32(grc_to_hw_addr(grc), tmp_addr, tmp_var);
		break;
	case NBL_CFG_CC_HIGH_RTT_FRACTION:
	case NBL_CFG_CC_RST_WIN_RTT_FRACTION:
		var_old = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);
		var = (var_old & 0xFFFFFF0F) | ((var & 0xF) << 4);
		break;
	case NBL_CFG_CC_LOW_RTT_FRACTION:
		var_old = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);
		var = (var_old & 0xFFFFFFF0) | (var & 0xF);
		break;
	case NBL_CFG_CC_HIGH_RTT_INT:
	case NBL_CFG_CC_RST_WIN_RTT_INT:
		var_old = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);
		var = (var_old & 0xFF0FFFFF) | ((var & 0xF) << 20);
		break;
	case NBL_CFG_CC_LOW_RTT_INT:
		var_old = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);
		var = (var_old & 0xFFF0FFFF) | ((var & 0xF) << 16);
		break;
	case NBL_CFG_CC_TXP_SENDREQ_DB_CFG:
		var_old = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);
		/* stop unit 1, send unit 0 */
		var = (var_old & 0xFFF00000) | (var & 0xFFFFF);
		break;
	default:
		break;
	}

	grc_wr32(grc_to_hw_addr(grc), offset_addr, var);
	grc_pr_debug("reg_addr:0x%llx, offset:%u var:%u\n", reg_addr, offset, var);
}

static void grc_set_vf_enable(struct nbl_grc *grc, u16 function_id, u8 enable)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	struct nbl_core_export *core_dev = &grc->core_dev;
	u64 reg_addr;
	u32 value;
	u16 index;

	index = NBL_HDMA_VF_BITMAP_BIT(function_id);

	reg_addr = NBL_HDMA_VF_ENABLE_ADDR(regs->hdma_base, function_id);

	value = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);
	grc_pr_debug("set vf enable,function_id=%u,enable=%u\n", function_id, enable);

	if (enable) {
		value |= BIT(index);
		grc_wr32(grc_to_hw_addr(grc), reg_addr, value);

		reg_addr = NBL_HDMA_VF_CLEAR_ADDR(regs->hdma_base, function_id);

		value = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);
		value |= BIT(index);
		grc_wr32(grc_to_hw_addr(grc), reg_addr, value);
	} else {
		value &= ~BIT(index);
		grc_wr32(grc_to_hw_addr(grc), reg_addr, value);
	}
}

static void grc_init_net_tc_tbl(struct nbl_grc *grc)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	u64 reg_addr;

	reg_addr = regs->txm_base;

	grc_wr32(grc_to_hw_addr(grc),
		 NBL_TXM_NET_TC_TBL_ADDR(reg_addr, 0), 0x0);
	grc_wr32(grc_to_hw_addr(grc),
		 NBL_TXM_NET_TC_TBL_ADDR(reg_addr, 1), 0x120);
	grc_wr32(grc_to_hw_addr(grc),
		 NBL_TXM_NET_TC_TBL_ADDR(reg_addr, 2), 0x240);
	grc_wr32(grc_to_hw_addr(grc),
		 NBL_TXM_NET_TC_TBL_ADDR(reg_addr, 3), 0x360);
	grc_wr32(grc_to_hw_addr(grc),
		 NBL_TXM_NET_TC_TBL_ADDR(reg_addr, 4), 0x480);
	grc_wr32(grc_to_hw_addr(grc),
		 NBL_TXM_NET_TC_TBL_ADDR(reg_addr, 5), 0x5A0);
	grc_wr32(grc_to_hw_addr(grc),
		 NBL_TXM_NET_TC_TBL_ADDR(reg_addr, 6), 0x6C0);
	grc_wr32(grc_to_hw_addr(grc),
		 NBL_TXM_NET_TC_TBL_ADDR(reg_addr, 7), 0x7E0);
}

static void nbl_set_vfid_vsi_map(struct nbl_grc *grc,
				 u16 function_id, u16 vsi_id, u8 valid)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	u64 reg_addr;
	union qm_vsi_mapping_tbl vsi_map = {};

	vsi_map.vf_id = function_id;
	vsi_map.valid = valid;

	reg_addr = NBL_QM_VSI_MAPPING_TBL_ADDR(regs->uqm_base, vsi_id);
	grc_pr_debug("UQM_VSI_MAPPING_TBL addr=0x%llx for vsi_id=%u\n", reg_addr, vsi_id);
	grc_wr32(grc_to_hw_addr(grc), reg_addr, vsi_map.data[0]);
}

/* Reserved legacy operation; the V2 RDMA path does not issue this request. */
static void nbl_enable_rdma_intrl(struct nbl_grc *grc, u16 global_msix_idx,
				  u8 devfn, u8 bus, u8 valid)
{
}

static void grc_get_rdma_abnormal_event(struct nbl_grc *grc)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	struct nbl_core_export *core_dev = &grc->core_dev;
	const struct nbl_grc_abnormal_module *module;
	u64 reg_addr;
	u32 value;
	u32 sub_module_int;
	int i = 1;
	DECLARE_BITMAP(ab_events, NBL_GRC_ABNORMAL_EVENT_BITS);

	reg_addr = regs->abnormal_modules[0].status_addr;
	value = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);
	grc_pr_debug("1.rdma top interrupt=0x%x\n", value);
	ab_events[0] = value;
	i = (int)find_next_bit(ab_events, regs->abnormal_module_count, i);
	grc_pr_debug("2.rdma submodule idx=%d\n", i);
	while (i < regs->abnormal_module_count) {
		module = &regs->abnormal_modules[i];
		reg_addr = module->status_addr;
		sub_module_int = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);

		grc_pr_err("[rdma][submodule_%s] generated abnormal event=%#x\n",
			      module->name, sub_module_int);

		grc_wr32(grc_to_hw_addr(grc), reg_addr, sub_module_int);
		i = (int)find_next_bit(ab_events, regs->abnormal_module_count, i + 1);
		grc_pr_debug("3.rdma submodule idx=%d\n", i);
	}
}

static u32 grc_get_hw_global_cfg_flag(struct nbl_grc *grc)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	struct nbl_core_export *core_dev = &grc->core_dev;
	u32 value;
	u64 reg_addr;
	u32 global_flag = 0;

	reg_addr = NBL_CQPP_REG_ADDR(regs->cqpp_base,
				     NBL_CQPP_GLOBAL_CFG_FLAG_OFF);
	value = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);
	global_flag = value & NBL_CQPP_GLOBAL_CFG_ENABLE;

	if (!global_flag) {
		value |= NBL_CQPP_GLOBAL_CFG_ENABLE;
		grc_wr32(grc_to_hw_addr(grc), reg_addr, value);
	}

	grc_pr_notice("get hw rdma global cfg flag=0x%x", global_flag);
	return global_flag;
}

static void nbl_resv_ctrl_dev_num(struct nbl_grc *grc)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	struct nbl_core_export *core_dev = &grc->core_dev;
	u32 ctrl_dev_mask = BIT(core_dev->eth_mode) - 1;
	u64 reg_addr = NBL_CQPP_REG_ADDR(regs->cqpp_base,
					 NBL_CQPP_INST_VFID_OFF);

	grc_wr32(grc_to_hw_addr(grc), reg_addr, ctrl_dev_mask);
}

static void nbl_freq_init(struct nbl_grc *grc)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	u32 freq = NBL_RDMA_SYS_CLK_SNIC_V2;
	union nbl_rxp_rnrtime_set_reg rnrtime_reg = {};
	u32 reg_addr = NBL_RXP_REG_ADDR(regs->rxp_base,
					NBL_RXP_RNRTIME_SET_OFF);
	u32 val_time;
	u32 rdma_top_base = regs->rdma_top_base;
	u32 glb_systime_1us_addr = NBL_RDMA_TOP_REG_ADDR(rdma_top_base,
					NBL_RDMA_TOP_GLB_SYSTIME_1US_OFF_DRACO);

	if (freq > NBL_RXP_FREQ_200M)
		val_time = NBL_RXP_TIMEVAL_U200M;
	else if (freq > NBL_RXP_FREQ_100M)
		val_time = NBL_RXP_TIMEVAL_U100M;
	else if (freq > NBL_RXP_FREQ_30M)
		val_time = NBL_RXP_TIMEVAL_U30M;
	else if (freq > NBL_RXP_FREQ_20M)
		val_time = NBL_RXP_TIMEVAL_U20M;
	else if (freq > NBL_RXP_FREQ_10M)
		val_time = NBL_RXP_TIMEVAL_U10M;
	else if (freq > NBL_RXP_FREQ_5M)
		val_time = NBL_RXP_TIMEVAL_U5M;
	else
		val_time = NBL_RXP_TIMEVAL_U1M;

	grc_pr_notice("set rxp rnr timelsb=%u", val_time);
	rnrtime_reg.rnrtime_lsb = val_time;
	grc_wr32(grc_to_hw_addr(grc), reg_addr, rnrtime_reg.data);

	reg_addr = glb_systime_1us_addr;
	grc_wr32(grc_to_hw_addr(grc), reg_addr, freq);
}

static void nbl_set_cqp_max_function_id(struct nbl_grc *grc, u16 max_vfid)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	union nbl_cqp_max_fun_id_reg max_fun_id_reg = {};
	u64 reg_addr = NBL_CQPP_REG_ADDR(regs->cqpp_base,
					 NBL_CQPP_MAX_FUN_ID_OFF);

	max_fun_id_reg.max_fun_id = max_vfid;
	max_fun_id_reg.max_fun_id_vld = 1;

	grc_pr_debug("set cqpp_max_vfid=%u", max_vfid);
	grc_wr32(grc_to_hw_addr(grc), reg_addr, max_fun_id_reg.data);
}

static void nbl_ceaq_eot_init(struct nbl_grc *grc)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	int depth = ARRAY_SIZE(hw_err_table);
	union nbl_eot_table_reg eot_reg = {};
	u64 reg_addr;
	int ix;

	for (ix = 0; ix < depth; ix++) {
		memset(&eot_reg, 0, sizeof(eot_reg));

		eot_reg.ae_flag = hw_err_table[ix].ae ? 1 : 0;
		eot_reg.abnorm_cqe_flag = hw_err_table[ix].abnormal_cqe ? 1 : 0;
		eot_reg.norm_cqe_flag = hw_err_table[ix].normal_cqe ? 1 : 0;
		eot_reg.drop_flag = hw_err_table[ix].drop ? 1 : 0;

		reg_addr = NBL_CEAQ_EOT_TBL_ADDR(regs->ceaq_base, ix);
		grc_wr32(grc_to_hw_addr(grc), reg_addr, eot_reg.data[0]);
	}
}

static void nbl_mask_rqdb_overflow_int(struct nbl_grc *grc)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	u64 reg_addr = NBL_NTFQP_INT_MASK_ADDR(regs->ntfqp_base);
	u32 value = NBL_NTFQP_RQDB_INT_MASK;

	grc_wr32(grc_to_hw_addr(grc), reg_addr, value);
}

static void grc_set_rdma_global_cfg(struct nbl_grc *grc)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	u16 max_function_id = NBL_RDMA_MAX_FUNCTION_ID;
	u64 reg_addr;

	reg_addr = NBL_RAQP_REG_ADDR(regs->raqp_base,
				     NBL_RAQP_DUP_READ_OPTIMIZE_OFF);
	grc_wr32(grc_to_hw_addr(grc), reg_addr, NBL_RAQP_DUP_READ_OPTIMIZE_ENABLE);

	nbl_resv_ctrl_dev_num(grc);
	nbl_freq_init(grc);
	nbl_set_cqp_max_function_id(grc, max_function_id);
	nbl_ceaq_eot_init(grc);
	nbl_mask_rqdb_overflow_int(grc);
	grc_init_net_tc_tbl(grc);
	grc_global_qos_default_cfg(grc);
}

static struct nbl_rdma_inst_info rdma_inst[NBL_INST_MAX] = {
	{ NBL_CQPP_INST_VFID_OFF, NBL_INST_VFID_SZ },
	{ NBL_CQPP_INST_SMAC_IP_OFF, NBL_INST_SMAC_IP_SZ },
	{ NBL_CQPP_INST_STAT_ID_OFF, NBL_INST_STAT_ID_SZ },
	{ NBL_CQPP_INST_CEQ_ID_OFF, NBL_INST_CEQ_ID_SZ },
};

static int grc_get_hw_instance_id(struct nbl_grc *grc, u8 inst_type, u16 *inst_id)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	struct nbl_core_export *core_dev = &grc->core_dev;
	u64 reg_addr;
	u32 value;
	int i = 0, j;
	u16 dw_sz;
	u16 step;
	u32 instance_id;
	u32 offset;
	struct nbl_rdma_inst_info *inst;

	if (inst_type >= NBL_INST_MAX || !inst_id) {
		grc_pr_err("invalid rdma instance type=%u,inst_id=%p\n", inst_type, inst_id);
		return -EINVAL;
	}

	inst = &rdma_inst[inst_type];
	dw_sz = DIV_ROUND_UP(inst->inst_size, NBL_INST_BM_BIT_SZ);
	reg_addr = regs->cqpp_base + inst->inst_base;

	if (inst_type == NBL_INST_SMAC_IP_INDEX) {
		/* Calculate number of gid registers allocated per PF */
		/* core_dev->eth_mode actually represents the total number of PFs in the device */
		step = DIV_ROUND_UP(dw_sz, core_dev->eth_mode);

		/* Calculate starting index for current PF's register block */
		/* Each PF gets an exclusive block of 'step' contiguous gid registers */
		i = core_dev->real_function * step;

		/* Update dw_sz to mark end address of current PF's register block */
		dw_sz = i + step;

		grc_pr_debug("inst_type=%u, rfunc=%u, eth_mode=%u, step=%u, i=%d, dw_sz=%u\n",
			inst_type, core_dev->real_function, core_dev->eth_mode, step, i, dw_sz);
	}

	for (; i < dw_sz; i++) {
		offset = i * NBL_INST_BM_DW_SZ;
		value = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr + offset);
		if (value == NBL_RDMA_FULL_INST_ID)
			continue;
		for (j = 0; j < NBL_INST_BM_BIT_SZ; j++) {
			if (unlikely(value & BIT(j)))
				continue;

			instance_id = i * NBL_INST_BM_BIT_SZ + j;
			if (unlikely(inst_type == NBL_INST_STAT_ID &&
					instance_id < NBL_RDMA_STAT_ID_START))
				continue;
			if (instance_id < inst->inst_size) {
				value |= BIT(j);
				*inst_id = instance_id;
				grc_wr32(grc_to_hw_addr(grc), reg_addr + offset, value);
				return 0;
			}

			break;
		}
	}

	grc_pr_err("no available rdma instance, its type=%u\n", inst_type);
	return -ENOENT;
}

static int grc_put_hw_instance_id(struct nbl_grc *grc, u8 inst_type, u16 inst_id)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	struct nbl_core_export *core_dev = &grc->core_dev;
	u64 reg_addr;
	u32 value;
	u32 dw_offset;
	struct nbl_rdma_inst_info *inst;

	if (inst_type >= NBL_INST_MAX) {
		grc_pr_err("invalid rdma instance type=%u\n", inst_type);
		return -EINVAL;
	}

	inst = &rdma_inst[inst_type];
	if (inst_id >= inst->inst_size) {
		grc_pr_err("invalid inst_id=%u,its type=%u\n", inst_id, inst_type);
		return -EINVAL;
	}

	dw_offset = (inst_id / NBL_INST_BM_BIT_SZ) * NBL_INST_BM_DW_SZ;
	reg_addr = regs->cqpp_base + inst->inst_base + dw_offset;

	value = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);
	value &= ~BIT(inst_id % NBL_INST_BM_BIT_SZ);
	grc_wr32(grc_to_hw_addr(grc), reg_addr, value);

	return 0;
}

static int grc_get_flush_status(struct nbl_grc *grc,
				u16 function_id, u32 check_base)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	struct nbl_core_export *core_dev = &grc->core_dev;
	u64 reg_addr;
	u32 check_offset;
	u32 flush_status = 0;

	switch (check_base) {
	case ASIC_ARMCQ_L_STATUS:
		check_offset = ASIC_ARMCQ_FLUSH_STATUS_L;
		break;
	case ASIC_ARMCQ_H_STATUS:
		check_offset = ASIC_ARMCQ_FLUSH_STATUS_H;
		break;
	case RQ_DB_STATUS:
		check_offset = RQDB_FLUSH_STATUS;
		break;
	default:
		return -1;
	}

	reg_addr = regs->ceaq_base + check_offset;
	flush_status = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);

	return (flush_status & (1 << (function_id % 32))) ? 1 : 0;
}

static void grc_set_mirror_prof_tbl(struct nbl_grc *grc, u16 mirr_id,
				    u16 vsi_id, bool enable_flag)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	u64 reg_addr;
	union epro_mirror_prof_tbl mirror_prof_tbl = {};

	mirror_prof_tbl.base_ad = ((u64)(MIRROR_NEXT_STG_ID | vsi_id)) << 48;
	mirror_prof_tbl.base_ad |= (NBL_QP_NUM_FOR_DUMP << 24);
	mirror_prof_tbl.base_ad |= (((MIRROR_RDMA_FLAG << 8) | MIRROR_RDMA_FLAG_MASK) << 8);
	mirror_prof_tbl.base_ab = (MIRROR_SET_DEST_ENABLE | (MIRROR_QPN_UDI_ID << 4));
	mirror_prof_tbl.vld = enable_flag ? 1 : 0;
	grc_pr_debug("mirror_prof_tbl.base_ad=0x%llx,base_ab=0x%x,vld=%u\n",
		     mirror_prof_tbl.base_ad, mirror_prof_tbl.base_ab, mirror_prof_tbl.vld);
	reg_addr = regs->epro_base + EPRO_MIRROR_PROF_TBL(mirr_id);
	grc_write_regs(grc_to_hw_addr(grc), reg_addr,
		       (u32 *)mirror_prof_tbl.data, sizeof(mirror_prof_tbl) / sizeof(u32));
}

static void grc_set_hw_dump_cfg(struct nbl_grc *grc, u16 vsi_id, u16 *rx_vlan_vsi_id,
				u16 vsi_num, u16 function_id, bool enable_flag, bool is_lag)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	struct nbl_core_export *core_dev = &grc->core_dev;
	u16 mirr_id = NBL_GET_MIRROR_ID(function_id);
	u64 reg_addr;
	union nbl_ped_qpn_udf_ext_reg qpn_udf_ext = {};
	union nbl_ped_tbl_mirr_enc mirr_enc_tbl = {};
	union nbl_am_udf_prf_tbl am_udf_tbl = {};
	union nbl_ipro_ivsi_tbl ivsi_tbl = {};
	union nbl_epro_evsi_tbl evsi_tbl = {};
	u16 rx_vlan_vsi_num;
	int i;

	if (!enable_flag) {
		grc_set_mirror_prof_tbl(grc, mirr_id, vsi_id, false);
		return;
	}

	/* 1. set ped qpn offset to get qpn from udf */
	qpn_udf_ext.oft = QPN_OFT_IN_UDF / PED_QPN_OFT_UNIT;
	qpn_udf_ext.vld = 1;

	reg_addr = NBL_PED_QPN_UDF_EXT_ADDR(regs->ped_base);
	grc_wr32(grc_to_hw_addr(grc), reg_addr, qpn_udf_ext.data[0]);

	/* 2. enable rdma dump mirror_id=120 */
	mirr_enc_tbl.mode = NBL_PED_RDMA_DUMP_MODE;

	reg_addr = NBL_PED_MIRR_ENC_TBL_ADDR(regs->ped_base, mirr_id);
	grc_write_regs(grc_to_hw_addr(grc), reg_addr,
		       mirr_enc_tbl.data, ARRAY_SIZE(mirr_enc_tbl.data));

	/* 3. set mirror_id offset in udf to write mirror_id=120 to udf */
	am_udf_tbl.set_udf0 = AM_UDF_VLD | AM_UDF_MIRROR_ID_OFT;
	reg_addr = regs->epro_base + EPRO_AM_UDF_PRF_TBL(AM_UDF_MIRROR_ID_IDX);
	grc_wr32(grc_to_hw_addr(grc), reg_addr, am_udf_tbl.data);

	reg_addr = regs->ipro_base + IPRO_AM_UDF_PRF_TBL(AM_UDF_MIRROR_ID_IDX);
	grc_wr32(grc_to_hw_addr(grc), reg_addr, am_udf_tbl.data);

	/* 4. set qpn offset in udf to write rdma dump dest qpn to udf */
	memset(&am_udf_tbl, 0, sizeof(am_udf_tbl));
	am_udf_tbl.set_udf0 = AM_UDF_VLD | EPRO_AM_UDF_QPN_LOW_OFT;
	am_udf_tbl.set_udf1 = AM_UDF_VLD | (ONLY_DATA_16BIT << 5) |
					EPRO_AM_UDF_QPN_HIGH_OFT;
	am_udf_tbl.set_udf2 = AM_UDF_VLD | (DATA_WITH_MASK_8BIT << 5) | EPRO_AM_UDF_RDMA_FLAG_OFT;
	reg_addr = regs->epro_base + EPRO_AM_UDF_PRF_TBL(AM_UDF_QPN_IDX);
	grc_wr32(grc_to_hw_addr(grc), reg_addr, am_udf_tbl.data);

	/* 5. set rdma dump dest qpn and vsi_id */
	grc_set_mirror_prof_tbl(grc, mirr_id, vsi_id, true);
	reg_addr = regs->ipro_base + IPRO_IVSI_TBL(vsi_id);
	grc_read_regs(grc_cdev_to_hw_addr(core_dev), reg_addr,
		      (u32 *)&ivsi_tbl, sizeof(ivsi_tbl) / sizeof(u32));
	grc_pr_debug("read ipro ivsi base_ab=%u,base_ad=0x%llx,vld=%u",
		     ivsi_tbl.base_ab, ivsi_tbl.base_ad, ivsi_tbl.vld);

	ivsi_tbl.base_ab |= (MIRROR_ID_UDI_ID << 4);
	ivsi_tbl.base_ad |= ((u64)(MIRROR_ID_VLD | mirr_id) << 40);
	grc_pr_debug("write ipro ivsi base_ab=%u,base_ad=0x%llx",
		     ivsi_tbl.base_ab, ivsi_tbl.base_ad);
	grc_write_regs(grc_to_hw_addr(grc), reg_addr,
		       (u32 *)ivsi_tbl.data, sizeof(ivsi_tbl) / sizeof(u32));

	reg_addr = regs->epro_base + NBL_EPRO_EVSI_TBL(vsi_id);
	grc_read_regs(grc_cdev_to_hw_addr(core_dev), reg_addr,
		      (u32 *)&evsi_tbl, sizeof(evsi_tbl) / sizeof(u32));
	grc_pr_debug("read epro evsi base_ab=%u,base_ad=0x%llx,vld=%u",
		     evsi_tbl.base_ab, evsi_tbl.base_ad, evsi_tbl.vld);

	evsi_tbl.base_ab |= (MIRROR_ID_UDI_ID << 4);
	evsi_tbl.base_ad |= ((u64)(MIRROR_ID_VLD | mirr_id) << 56);
	grc_pr_debug("write epro evsi base_ab=%u,base_ad=0x%llx",
		     evsi_tbl.base_ab, evsi_tbl.base_ad);
	grc_write_regs(grc_to_hw_addr(grc), reg_addr,
		       (u32 *)evsi_tbl.data, sizeof(evsi_tbl) / sizeof(u32));

	/**
	 * 1.get first element from rx_vlan_vsi_id array in non bond case
	 * 2.get first and second elements from rx_vlan_vsi_id array in bond case
	 * 3.get frist and second elements from rx_vlan_vsi_id in 4 ports type, 4 ports
	 * draco card only support 2 port bond
	 */
	rx_vlan_vsi_num = is_lag ? vsi_num : 1;
	rx_vlan_vsi_num = min_t(u16, rx_vlan_vsi_num, NBL_RDMA_LAG_MBRS_MAX);
	for (i = 0; i < rx_vlan_vsi_num; i++) {
		memset(&evsi_tbl, 0, sizeof(evsi_tbl));
		reg_addr = regs->epro_base + NBL_EPRO_EVSI_TBL(rx_vlan_vsi_id[i]);
		grc_read_regs(grc_cdev_to_hw_addr(core_dev), reg_addr,
			(u32 *)&evsi_tbl, sizeof(evsi_tbl) / sizeof(u32));
		evsi_tbl.base_ab |= (MIRROR_ID_UDI_ID << 4);
		evsi_tbl.base_ad |= ((u64)(MIRROR_ID_VLD | mirr_id) << 56);
		grc_write_regs(grc_to_hw_addr(grc), reg_addr,
			(u32 *)evsi_tbl.data, sizeof(evsi_tbl) / sizeof(u32));
	}
}

static void grc_clear_hw_cache(struct nbl_grc *grc, u32 cache_type)
{
	const struct nbl_grc_register_layout *regs = grc->product->regs;
	struct nbl_core_export *core_dev = &grc->core_dev;
	const struct nbl_grc_cache_layout *cache;
	u32 i;
	u32 fifo_thr_high;
	u32 fifo_thr_low;
	u32 cam_afull_thr;

	for (i = 0; i < regs->cache_count; i++) {
		cache = &regs->caches[i];
		if (cache->type == cache_type) {
			fifo_thr_high = grc_rd32(grc_cdev_to_hw_addr(core_dev),
						 cache->high_threshold_addr);
			fifo_thr_low = grc_rd32(grc_cdev_to_hw_addr(core_dev),
						cache->low_threshold_addr);
			cam_afull_thr = grc_rd32(grc_cdev_to_hw_addr(core_dev),
						 cache->almost_full_threshold_addr);

			/* 1. config these regs to cache max depth */
			grc_wr32(grc_to_hw_addr(grc), cache->high_threshold_addr,
				 cache->depth);
			grc_wr32(grc_to_hw_addr(grc), cache->low_threshold_addr,
				 cache->depth);
			grc_wr32(grc_to_hw_addr(grc), cache->almost_full_threshold_addr,
				 cache->depth);

			/* 2. recover the default value for these regs */
			grc_wr32(grc_to_hw_addr(grc), cache->high_threshold_addr,
				 fifo_thr_high);
			grc_wr32(grc_to_hw_addr(grc), cache->low_threshold_addr,
				 fifo_thr_low);
			grc_wr32(grc_to_hw_addr(grc), cache->almost_full_threshold_addr,
				 cam_afull_thr);
			return;
		}
	}
}

const struct nbl_grc_resource_ops grc_resource_ops = {
	.set_sd_range = grc_set_sd_range,
	.get_sd_range = __grc_get_sd_range,
	.set_bdf_func_id_map = grc_set_bdf_func_id_map,
	.set_hw_pf_tbl = grc_set_pf_tbl,
	.set_cqp_info = grc_set_cqp_info,
	.set_cqp_pi = grc_set_cqp_pi,
	.set_src_addr_info = grc_set_src_addr_info,
	.set_rdma_pfid_map_tbl = nbl_set_rdma_pfid_map_tbl,
	.set_cc_params = grc_set_cc_params,
	.set_vf_enable = grc_set_vf_enable,
	.set_vfid_vsi_map = nbl_set_vfid_vsi_map,
	.ena_rdma_intrl = nbl_enable_rdma_intrl,
	.get_abnormal_event = grc_get_rdma_abnormal_event,
	.get_hw_inst_id = grc_get_hw_instance_id,
	.put_hw_inst_id = grc_put_hw_instance_id,
	.hw_get_flush_status = grc_get_flush_status,
	.set_hw_dump_cfg = grc_set_hw_dump_cfg,
	.clear_hw_cache = grc_clear_hw_cache,
};

const struct nbl_grc_dsch_ops grc_dsch_ops = {
	.set_rdma_dsch = grc_set_dsch_tbl,
	.update_rdma_dsch = nbl_update_rdma_dsch,
};

const struct nbl_grc_stat_ops grc_stat_ops = {
	.set_hw_stat = grc_set_hw_stat,
	.get_hw_stat = grc_get_hw_stat,
	.enable_errcode_hw_stat = grc_enable_errcode_hw_stat,
	.get_hw_status = grc_get_hw_status,
};

const struct nbl_grc_global_ops grc_global_ops = {
	.get_hw_global_cfg_flag = grc_get_hw_global_cfg_flag,
	.set_hw_global_cfg = grc_set_rdma_global_cfg,
};
