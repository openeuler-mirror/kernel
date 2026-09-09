// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include "grc_hw_rdma.h"
#include "grc_gid.h"

static u32 grc_rd32(u8 __iomem *addr, u64 reg)
{
	return readl(addr + (reg));
}

static void grc_wr32(u8 __iomem *addr, u64 reg, u32 value)
{
	writel((value), (addr + (reg)));
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
	/* reg_off, msb drop norm_cqe abnorm_cqe ae err_code */
	{/* 0x1000 */ 0, 1, 0, 0, 0, 0x0},
	{/* 0x1004 */ 0, 1, 0, 0, 0, 0x1},
	{/* 0x1008 */ 0, 1, 0, 0, 0, 0x2},
	{/* 0x100c */ 0, 1, 0, 0, 0, 0x3},
	{/* 0x1010 */ 0, 1, 0, 0, 0, 0x4},
	{/* 0x1014 */ 0, 1, 0, 0, 0, 0x5},
	{/* 0x1018 */ 0, 1, 0, 0, 0, 0x6},
	{/* 0x101c */ 0, 1, 0, 0, 0, 0x7},
	{/* 0x1020 */ 0, 1, 0, 0, 0, 0x8},
	{/* 0x1024 */ 0, 1, 0, 0, 0, 0x9},
	{/* 0x1028 */ 0, 1, 0, 0, 0, 0xA},
	{/* 0x102c */ 0, 1, 0, 0, 0, 0xB},
	{/* 0x1030 */ 0, 0, 0, 0, 1, 0xC},
	{/* 0x1034 */ 0, 0, 0, 0, 1, 0xD},
	{/* 0x1038 */ 0, 0, 0, 0, 1, 0xE},
	{/* 0x103c */ 0, 0, 0, 0, 1, 0xF},
	{/* 0x1040 */ 0, 0, 0, 0, 1, 0x10},
	{/* 0x1044 */ 0, 0, 0, 0, 1, 0x11},
	{/* 0x1048 */ 0, 0, 0, 0, 1, 0x12},
	{/* 0x104c */ 0, 0, 0, 0, 1, 0x13},
	{/* 0x1050 */ 0, 0, 0, 0, 1, 0x14},
	{/* 0x1054 */ 0, 0, 0, 0, 1, 0x15},
	{/* 0x1058 */ 0, 1, 0, 0, 0, 0x16},
	{/* 0x105c */ 0, 1, 0, 0, 0, 0x17},
	{/* 0x1060 */ 0, 0, 0, 0, 1, 0x18},
	{/* 0x1064 */ 0, 1, 0, 0, 0, 0x19},
	{/* 0x1068 */ 0, 0, 0, 1, 1, 0x1A},
	{/* 0x106c */ 0, 0, 0, 1, 0, 0x1B},
	{/* 0x1070 */ 0, 0, 0, 1, 1, 0x1C},
	{/* 0x1074 */ 0, 0, 0, 1, 1, 0x1D},
	{/* 0x1078 */ 0, 0, 0, 1, 1, 0x1E},
	{/* 0x107c */ 0, 0, 0, 1, 1, 0x1F},
	{/* 0x1080 */ 0, 1, 0, 0, 0, 0x20},
	{/* 0x1084 */ 0, 1, 0, 0, 0, 0x21},
	{/* 0x1088 */ 0, 1, 0, 0, 0, 0x22},
	{/* 0x108c */ 0, 1, 0, 0, 0, 0x23},
	{/* 0x1090 */ 0, 1, 0, 0, 0, 0x24},
	{/* 0x1094 */ 0, 1, 0, 0, 0, 0x25},
	{/* 0x1098 */ 0, 1, 0, 0, 0, 0x26},
	{/* 0x109c */ 0, 1, 0, 0, 0, 0x27},
	{/* 0x10a0 */ 0, 1, 0, 0, 0, 0x28},
	{/* 0x10a4 */ 0, 1, 0, 0, 0, 0x29},
	{/* 0x10a8 */ 0, 0, 0, 0, 0, 0x2A},
	{/* 0x10ac */ 0, 0, 0, 0, 0, 0x2B},
	{/* 0x10b0 */ 0, 1, 0, 0, 0, 0x2C},
	{/* 0x10b4 */ 0, 0, 0, 0, 0, 0x2D},
	{/* 0x10b8 */ 0, 0, 0, 0, 0, 0x2E},
	{/* 0x10bc */ 0, 1, 0, 0, 0, 0x2F},
	{/* 0x10c0 */ 0, 0, 0, 1, 1, 0x30},
	{/* 0x10c4 */ 0, 0, 0, 1, 1, 0x31},
	{/* 0x10c8 */ 0, 0, 0, 1, 1, 0x32},
	{/* 0x10cc */ 0, 0, 0, 1, 1, 0x33},
	{/* 0x10d0 */ 0, 0, 0, 1, 1, 0x34},
	{/* 0x10d4 */ 0, 0, 0, 1, 1, 0x35},
	{/* 0X10d8 */ 0, 0, 0, 1, 1, 0x36},
	{/* 0x10dc */ 0, 1, 0, 0, 0, 0x37},
	{/* 0x10e0 */ 0, 0, 0, 1, 1, 0x38},
	{/* 0x10e4 */ 0, 0, 0, 1, 1, 0x39},
	{/* 0x10e8 */ 0, 0, 0, 1, 1, 0x3A},
	{/* 0x10ec */ 0, 0, 0, 1, 1, 0x3B},
	{/* 0x10f0 */ 0, 0, 0, 1, 1, 0x3C},
	{/* 0x10f4 */ 0, 0, 0, 1, 1, 0x3D},
	{/* 0x10f8 */ 0, 0, 0, 1, 1, 0x3E},
	{/* 0x10fc */ 0, 0, 0, 1, 1, 0x3F},
	{/* 0x1100 */ 0, 0, 0, 1, 1, 0x40},
	{/* 0x1104 */ 0, 1, 0, 0, 0, 0x41},
	{/* 0x1108 */ 0, 1, 0, 0, 0, 0x42},
	{/* 0x110c */ 0, 1, 0, 0, 0, 0x43},
	{/* 0x1110 */ 0, 0, 0, 0, 1, 0x44},
	{/* 0x1114 */ 0, 1, 0, 0, 0, 0x45},
	{/* 0x1118 */ 0, 1, 0, 0, 0, 0x46},
	{/* 0x111c */ 0, 1, 0, 0, 0, 0x47},
	{/* 0x1120 */ 0, 0, 0, 0, 1, 0x48},
	{/* 0x1124 */ 0, 1, 0, 0, 0, 0x49},
	{/* 0x1128 */ 0, 0, 0, 1, 1, 0x4a},
	{/* 0x112c */ 0, 0, 0, 1, 1, 0x4b},
	{/* 0x1130 */ 0, 1, 0, 0, 0, 0x4c},
	{/* 0x1134 */ 0, 1, 0, 0, 0, 0x4d},
	{/* 0x1138 */ 0, 1, 0, 0, 0, 0x4e},
	{/* 0x113c */ 0, 1, 0, 0, 0, 0x4f},
	{/* 0x1140 */ 0, 1, 0, 0, 0, 0x50},
	{/* 0x1144 */ 0, 1, 0, 0, 0, 0x51},
	{/* 0x1148 */ 0, 1, 0, 0, 0, 0x52},
	{/* 0x114c */ 0, 1, 0, 0, 0, 0x53},
	{/* 0x1150 */ 0, 1, 0, 0, 0, 0x54},
	{/* 0x1154 */ 0, 0, 0, 1, 1, 0x55},
	{/* 0x1158 */ 0, 0, 0, 0, 1, 0x56},
	{/* 0x115c */ 0, 0, 0, 1, 1, 0x57},
	{/* 0x1160 */ 0, 1, 0, 0, 0, 0x58},
	{/* 0x1164 */ 0, 0, 0, 0, 0, 0x59},
	{/* 0x1168 */ 0, 1, 0, 0, 0, 0x5a},
	{/* 0x116c */ 0, 0, 0, 1, 1, 0x5b},
	{/* 0x1170 */ 0, 0, 0, 0, 1, 0x5c},
	{/* 0x1174 */ 0, 1, 0, 0, 0, 0x5d},
	{/* 0x1178 */ 0, 1, 0, 0, 0, 0x5e},
	{/* 0x117c */ 0, 1, 0, 0, 0, 0x5f},
	{/* 0x1180 */ 0, 0, 0, 1, 1, 0x60},
	{/* 0x1184 */ 0, 0, 0, 1, 1, 0x61},
	{/* 0x1188 */ 0, 0, 0, 1, 1, 0x62},
	{/* 0x118c */ 0, 0, 0, 1, 1, 0x63},
	{/* 0x1190 */ 0, 0, 0, 1, 1, 0x64},
	{/* 0x1194 */ 0, 0, 0, 1, 1, 0x65},
	{/* 0x1198 */ 0, 0, 0, 1, 1, 0x66},
	{/* 0x119c */ 0, 0, 0, 1, 1, 0x67},
	{/* 0x11a0 */ 0, 0, 0, 1, 1, 0x68},
	{/* 0x11a4 */ 0, 0, 0, 1, 1, 0x69},
	{/* 0x11a8 */ 0, 0, 0, 1, 1, 0x6A},
	{/* 0x11ac */ 0, 0, 0, 1, 1, 0x6B},
	{/* 0x11b0 */ 0, 0, 0, 1, 1, 0x6C},
	{/* 0x11b4 */ 0, 0, 0, 1, 1, 0x6D},
	{/* 0x11b8 */ 0, 0, 0, 1, 1, 0x6E},
	{/* 0x11bc */ 0, 0, 0, 1, 1, 0x6F},
	{/* 0x11c0 */ 0, 0, 0, 1, 1, 0x70},
	{/* 0x11c4 */ 0, 0, 0, 1, 1, 0x71},
	{/* 0x11c8 */ 0, 1, 0, 0, 0, 0x72},
	{/* 0x11cc */ 0, 1, 0, 0, 0, 0x73},
	{/* 0x11d0 */ 0, 1, 0, 0, 0, 0x74},
	{/* 0x11d4 */ 0, 0, 0, 0, 1, 0x75},
	{/* 0x11d8 */ 0, 0, 0, 1, 1, 0x76},
	{/* 0x11dc */ 0, 0, 0, 0, 1, 0x77},
	{/* 0x11e0 */ 0, 1, 0, 0, 0, 0x78},
	{/* 0x11e4 */ 0, 0, 0, 0, 1, 0x79},
	{/* 0x11e8 */ 0, 0, 0, 0, 1, 0x7a},
	{/* 0x11ec */ 0, 1, 0, 0, 0, 0x7b},
	{/* 0x11f0 */ 0, 1, 0, 0, 0, 0x7c},
	{/* 0x11f4 */ 0, 1, 0, 0, 0, 0x7d},
	{/* 0x11f8 */ 0, 1, 0, 0, 0, 0x7e},
	{/* 0x11fc */ 0, 1, 0, 0, 0, 0x7f},

	/* MSB=1 */
	{/* 0x1200 */ 1, 1, 0, 0, 0, 0x0},
	{/* 0x1204 */ 1, 1, 0, 0, 0, 0x1},
	{/* 0x1208 */ 1, 1, 0, 0, 0, 0x2},
	{/* 0x120c */ 1, 1, 0, 0, 0, 0x3},
	{/* 0x1210 */ 1, 1, 0, 0, 0, 0x4},
	{/* 0x1214 */ 1, 1, 0, 0, 0, 0x5},
	{/* 0x1218 */ 1, 1, 0, 0, 0, 0x6},
	{/* 0x121c */ 1, 1, 0, 0, 0, 0x7},
	{/* 0x1220 */ 1, 1, 0, 0, 0, 0x8},
	{/* 0x1224 */ 1, 1, 0, 0, 0, 0x9},
	{/* 0x1228 */ 1, 1, 0, 0, 0, 0xA},
	{/* 0x122c */ 1, 1, 0, 0, 0, 0xB},
	{/* 0x1230 */ 1, 0, 0, 0, 1, 0xC},
	{/* 0x1234 */ 1, 0, 0, 0, 1, 0xD},
	{/* 0x1238 */ 1, 0, 0, 0, 1, 0xE},
	{/* 0x123c */ 1, 0, 0, 0, 1, 0xF},
	{/* 0x1240 */ 1, 0, 0, 0, 1, 0x10},
	{/* 0x1244 */ 1, 0, 0, 0, 1, 0x11},
	{/* 0x1248 */ 1, 0, 0, 0, 1, 0x12},
	{/* 0x124c */ 1, 0, 0, 0, 1, 0x13},
	{/* 0x1250 */ 1, 0, 0, 0, 1, 0x14},
	{/* 0x1254 */ 1, 0, 0, 0, 1, 0x15},
	{/* 0x1258 */ 1, 1, 0, 0, 0, 0x16},
	{/* 0x125c */ 1, 1, 0, 0, 0, 0x17},
	{/* 0x1260 */ 1, 0, 0, 0, 1, 0x18},
	{/* 0x1264 */ 1, 1, 0, 0, 0, 0x19},
	{/* 0x1268 */ 1, 0, 0, 1, 1, 0x1A},
	{/* 0x126c */ 1, 0, 0, 1, 0, 0x1B},
	{/* 0x1270 */ 1, 0, 0, 1, 1, 0x1C},
	{/* 0x1274 */ 1, 0, 0, 1, 1, 0x1D},
	{/* 0x1278 */ 1, 0, 0, 1, 1, 0x1E},
	{/* 0x127c */ 1, 0, 0, 1, 1, 0x1F},
	{/* 0x1280 */ 1, 1, 0, 0, 0, 0x20},
	{/* 0x1284 */ 1, 1, 0, 0, 0, 0x21},
	{/* 0x1288 */ 1, 1, 0, 0, 0, 0x22},
	{/* 0x128c */ 1, 1, 0, 0, 0, 0x23},
	{/* 0x1290 */ 1, 1, 0, 0, 0, 0x24},
	{/* 0x1294 */ 1, 1, 0, 0, 0, 0x25},
	{/* 0x1298 */ 1, 1, 0, 0, 0, 0x26},
	{/* 0x129c */ 1, 1, 0, 0, 0, 0x27},
	{/* 0x12a0 */ 1, 1, 0, 0, 0, 0x28},
	{/* 0x12a4 */ 1, 1, 0, 0, 0, 0x29},
	{/* 0x12a8 */ 1, 0, 1, 0, 0, 0x2A},
	{/* 0x12ac */ 1, 0, 1, 0, 0, 0x2B},
	{/* 0x12b0 */ 1, 0, 1, 0, 0, 0x2C},
	{/* 0x12b4 */ 1, 0, 1, 0, 0, 0x2D},
	{/* 0x12b8 */ 1, 0, 1, 0, 0, 0x2E},
	{/* 0x12bc */ 1, 1, 0, 0, 0, 0x2F},
	{/* 0x12c0 */ 1, 0, 0, 1, 1, 0x30},
	{/* 0x12c4 */ 1, 0, 0, 1, 1, 0x31},
	{/* 0x12c8 */ 1, 0, 0, 1, 1, 0x32},
	{/* 0x12cc */ 1, 0, 0, 1, 1, 0x33},
	{/* 0x12d0 */ 1, 0, 0, 1, 1, 0x34},
	{/* 0x12d4 */ 1, 0, 0, 1, 1, 0x35},
	{/* 0X12d8 */ 1, 0, 0, 1, 1, 0x36},
	{/* 0x12dc */ 1, 1, 0, 0, 0, 0x37},
	{/* 0x12e0 */ 1, 0, 0, 0, 1, 0x38},
	{/* 0x12e4 */ 1, 0, 0, 0, 1, 0x39},
	{/* 0x12e8 */ 1, 0, 0, 0, 1, 0x3A},
	{/* 0x12ec */ 1, 0, 0, 0, 1, 0x3B},
	{/* 0x12f0 */ 1, 0, 0, 0, 1, 0x3C},
	{/* 0x12f4 */ 1, 0, 0, 0, 1, 0x3D},
	{/* 0x12f8 */ 1, 0, 0, 1, 1, 0x3E},
	{/* 0x12fc */ 1, 0, 0, 1, 1, 0x3F},
	{/* 0x1200 */ 1, 0, 0, 1, 1, 0x40},
	{/* 0x1204 */ 1, 1, 0, 0, 0, 0x41},
	{/* 0x1208 */ 1, 1, 0, 0, 0, 0x42},
	{/* 0x120c */ 1, 1, 0, 0, 0, 0x43},
	{/* 0x1210 */ 1, 0, 0, 0, 1, 0x44},
	{/* 0x1214 */ 1, 1, 0, 0, 0, 0x45},
	{/* 0x1218 */ 1, 1, 0, 0, 0, 0x46},
	{/* 0x121c */ 1, 1, 0, 0, 0, 0x47},
	{/* 0x1220 */ 1, 0, 0, 0, 1, 0x48},
	{/* 0x1224 */ 1, 1, 0, 0, 0, 0x49},
	{/* 0x1228 */ 1, 0, 0, 1, 1, 0x4a},
	{/* 0x122c */ 1, 0, 0, 1, 1, 0x4b},
	{/* 0x1230 */ 1, 1, 0, 0, 0, 0x4c},
	{/* 0x1234 */ 1, 1, 0, 0, 0, 0x4d},
	{/* 0x1238 */ 1, 1, 0, 0, 0, 0x4e},
	{/* 0x123c */ 1, 1, 0, 0, 0, 0x4f},
	{/* 0x1240 */ 1, 1, 0, 0, 0, 0x50},
	{/* 0x1244 */ 1, 1, 0, 0, 0, 0x51},
	{/* 0x1248 */ 1, 1, 0, 0, 0, 0x52},
	{/* 0x124c */ 1, 1, 0, 0, 0, 0x53},
	{/* 0x1250 */ 1, 1, 0, 0, 0, 0x54},
	{/* 0x1254 */ 1, 0, 0, 1, 1, 0x55},
	{/* 0x1258 */ 1, 0, 0, 0, 1, 0x56},
	{/* 0x125c */ 1, 0, 0, 1, 1, 0x57},
	{/* 0x1260 */ 1, 1, 0, 0, 0, 0x58},
	{/* 0x1264 */ 1, 0, 0, 0, 0, 0x59},
	{/* 0x1268 */ 1, 1, 0, 0, 0, 0x5a},
	{/* 0x126c */ 1, 0, 0, 1, 1, 0x5b},
	{/* 0x1270 */ 1, 0, 0, 0, 1, 0x5c},
	{/* 0x1274 */ 1, 1, 0, 0, 0, 0x5d},
	{/* 0x1278 */ 1, 1, 0, 0, 0, 0x5e},
	{/* 0x127c */ 1, 1, 0, 0, 0, 0x5f},
	{/* 0x1280 */ 1, 0, 0, 1, 1, 0x60},
	{/* 0x1284 */ 1, 0, 0, 1, 1, 0x61},
	{/* 0x1288 */ 1, 0, 0, 1, 1, 0x62},
	{/* 0x128c */ 1, 0, 0, 1, 1, 0x63},
	{/* 0x1290 */ 1, 0, 0, 1, 1, 0x64},
	{/* 0x1294 */ 1, 0, 0, 1, 1, 0x65},
	{/* 0x1298 */ 1, 0, 0, 1, 1, 0x66},
	{/* 0x129c */ 1, 0, 0, 1, 1, 0x67},
	{/* 0x12a0 */ 1, 0, 0, 1, 1, 0x68},
	{/* 0x12a4 */ 1, 0, 0, 1, 1, 0x69},
	{/* 0x12a8 */ 1, 0, 0, 1, 1, 0x6A},
	{/* 0x12ac */ 1, 0, 0, 1, 1, 0x6B},
	{/* 0x12b0 */ 1, 0, 0, 1, 1, 0x6C},
	{/* 0x12b4 */ 1, 0, 0, 1, 1, 0x6D},
	{/* 0x12b8 */ 1, 0, 0, 1, 1, 0x6E},
	{/* 0x12bc */ 1, 0, 0, 1, 1, 0x6F},
	{/* 0x12c0 */ 1, 0, 0, 1, 1, 0x70},
	{/* 0x12c4 */ 1, 0, 0, 1, 1, 0x71},
	{/* 0x12c8 */ 1, 1, 0, 0, 0, 0x72},
	{/* 0x12cc */ 1, 1, 0, 0, 0, 0x73},
	{/* 0x12d0 */ 1, 1, 0, 0, 0, 0x74},
	{/* 0x12d4 */ 1, 1, 0, 0, 1, 0x75},
	{/* 0x12d8 */ 1, 0, 0, 1, 1, 0x76},
	{/* 0x12dc */ 1, 0, 0, 0, 1, 0x77},
	{/* 0x12e0 */ 1, 1, 0, 0, 0, 0x78},
	{/* 0x12e4 */ 1, 0, 0, 0, 1, 0x79},
	{/* 0x12e8 */ 1, 0, 0, 0, 1, 0x7a},
	{/* 0x12ec */ 1, 1, 0, 0, 0, 0x7b},
	{/* 0x12f0 */ 1, 1, 0, 0, 0, 0x7c},
	{/* 0x12f4 */ 1, 1, 0, 0, 0, 0x7d},
	{/* 0x12f8 */ 1, 1, 0, 0, 0, 0x7e},
	{/* 0x12fc */ 1, 1, 0, 0, 0, 0x7f},
};

#define grc_cdev_to_hw_addr(cdev)  ((cdev)->hw_addr)

void grc_query_fmr_nofnece_info(struct nbl_grc *grc, struct nbl_chan_rdma_resp *mbx_resp)
{
	u8 fmr_nofence_en;
	u32 temp;

	struct grc_resp_msg resp_msg;

	resp_msg.msg[0] = NBL_GRC_MSG_RESP_OK;

	temp = grc_rd32(grc_cdev_to_hw_addr(&grc->core_dev),
			NBL_REG_TXMR_FMR_NOFENCE);

	if (temp & NBL_TXMR_NOFENCE_BIT0)
		fmr_nofence_en = true;
	else
		fmr_nofence_en = false;

	resp_msg.msg_len = sizeof(fmr_nofence_en) + 1;
	mbx_resp->data_len = min(sizeof(mbx_resp->resp_data), sizeof(resp_msg));
	memcpy(resp_msg.msg + 1, &fmr_nofence_en, sizeof(fmr_nofence_en));
	memcpy(mbx_resp->resp_data, &resp_msg, mbx_resp->data_len);
}

void nbl_set_fmr_nofence(struct nbl_grc *grc, u8 enable)
{
	u32 temp = 0;

	temp = grc_rd32(grc_cdev_to_hw_addr(&grc->core_dev),
			NBL_REG_TXMR_FMR_NOFENCE);
	/*set read resp nocheck*/
	temp |= NBL_TXMR_READ_RESP_NOCHECK_BIT2;
	if (enable) {
		temp |= NBL_TXMR_NOFENCE_BIT0;
		grc_wr32(grc_cdev_to_hw_addr(&grc->core_dev),
			 NBL_REG_TXMR_FMR_NOFENCE, temp);
	} else {
		temp &= ~((u32)NBL_TXMR_NOFENCE_BIT0);
		grc_wr32(grc_cdev_to_hw_addr(&grc->core_dev),
			 NBL_REG_TXMR_FMR_NOFENCE, temp);
	}
}

static void grc_set_sd_range(struct nbl_core_dev_info *core_dev,
			     u16 function_id, u32 sd_start, u32 sd_cnt, bool valid)
{
	union nbl_sd_range_tbl_reg sd_range_tbl = {0};
	u64 reg_addr;
	u32 *value;
	u32 sd_range;

	reg_addr = NBL_REG_SDBASE_TBL_RAM + function_id * sizeof(union nbl_sd_range_tbl_reg);

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

	grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, *value);
}

static void __grc_get_sd_range(struct nbl_core_dev_info *core_dev, u16 function_id,
			       u32 *sd_start, u32 *sd_cnt)
{
	union nbl_sd_range_tbl_reg sd_range_tbl = {0};
	void *reg_addr;
	u32 *value = (u32 *)&sd_range_tbl;

	reg_addr = core_dev->hw_addr + NBL_REG_SDBASE_TBL_RAM;
	*value = readl(reg_addr + function_id * sizeof(union nbl_sd_range_tbl_reg));

	*sd_start = sd_range_tbl.sd_base_idx;
	*sd_cnt = sd_range_tbl.sd_max_num;
	grc_pr_debug("got sd_range_tbl(start=%u,cnt=%u,vld=%u) for func_id=%u\n",
		     *sd_start, *sd_cnt, sd_range_tbl.sd_base_info_vld, function_id);
}

static void grc_set_bdf_func_id_map(struct nbl_core_dev_info *core_dev, u32 host_id,
				    u32 bdf_num, u16 func_id)
{
	union nbl_hdma_bdf_tbl_reg bdf_tbl = {0};
	u64 reg_addr;
	u32 *value;

	grc_pr_debug("set bdf_tbl reg for func_id=%u,host_id=%u,bdf_num=0x%x\n",
		     func_id, host_id, bdf_num);

	memcpy(bdf_tbl.data, &bdf_num, sizeof(union nbl_hdma_bdf_tbl_reg));
	bdf_tbl.host_en = (host_id == HOST_ID_TYPE_ECPU ? 0 : 1);

	grc_pr_debug("set bdf_tbl bus=%u,dev=%u,func=%u,host_id=%u,func_id=%u,host_en=%u\n",
		     bdf_tbl.bus_id, bdf_tbl.device_id, bdf_tbl.function_id,
		     host_id, func_id, bdf_tbl.host_en);

	value = (u32 *)&bdf_tbl;

	reg_addr = NBL_REG_HDMA_BDF_TBL + func_id * sizeof(union nbl_hdma_bdf_tbl_reg);
	grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, *value);
}

static struct grc_dsch_spec dsch_id_spec = {
	.min_net_shaping_id = NBL_GRC_MIN_NET_SHAPING_ID,
	.max_net_shaping_id = NBL_GRC_MAX_NET_SHAPING_ID,
	.min_grp_shaping_id = NBL_GRC_MIN_GRP_SHAPING_ID,
	.max_grp_shaping_id = NBL_GRC_MAX_GRP_SHAPING_ID
};

static struct grc_dsch_spec *grc_get_dsch_spec(void)
{
	return &dsch_id_spec;
}

static void grc_set_rdma_net_en(struct nbl_core_dev_info *core_dev, u16 function_id)
{
	u64 reg_addr;
	u32 rdma_net_en_val = 0;
	u32 index = function_id % DSCH_RDMA_NET_EN_REGS_SIZE;

	reg_addr = DSCH_RDMA_LNET_EN + 4 * (function_id / DSCH_RDMA_NET_EN_REGS_SIZE);
	rdma_net_en_val = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);
	rdma_net_en_val |= ((u32)1 << index);
	grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, rdma_net_en_val);
}

static void grc_clear_rdma_net_en(struct nbl_core_dev_info *core_dev, u16 function_id)
{
	u64 reg_addr;
	u32 rdma_net_en_val = 0;
	u32 index = function_id % DSCH_RDMA_NET_EN_REGS_SIZE;

	reg_addr = DSCH_RDMA_LNET_EN + 4 * (function_id / DSCH_RDMA_NET_EN_REGS_SIZE);
	rdma_net_en_val = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);
	rdma_net_en_val &= ~((u32)1 << index);
	grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, rdma_net_en_val);
}

static bool grc_check_netnode_if_flush(struct nbl_core_dev_info *core_dev, u16 function_id)
{
	u64 reg_addr;
	bool rdma_tc_q_flush = true;
	bool rdma_dbq_flush = true;
	u16 net_tc;
	u32 attr_val;
	union rdma_tc_q_list_attr_tbl tc_q_list = {0};

	reg_addr = DSCH_RDMA_DBQ_ATTR_TBL(function_id);
	for (net_tc = 0; net_tc < DSCH_RDMA_NET_TC_SIZE; net_tc++) {
		attr_val = grc_rd32(grc_cdev_to_hw_addr(core_dev),
				    reg_addr + net_tc * DSCH_RDMA_DBQ_ATTR_SIZE);
		if (attr_val & DSCH_RDMA_DBQ_ATTR_TBL_NEMPTY) {
			rdma_dbq_flush = false;
			break;
		}
	}

	reg_addr = DSCH_RDMA_TC_Q_LIST_ATTR_TBL(function_id);
	for (net_tc = 0; net_tc < DSCH_RDMA_NET_TC_SIZE; net_tc++) {
		tc_q_list.data[0] = grc_rd32(grc_cdev_to_hw_addr(core_dev),
					     reg_addr + net_tc * DSCH_RDMA_TC_Q_LIST_ATTR_SIZE);
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

static bool grc_check_netnode_is_init(struct nbl_core_dev_info *core_dev, u16 net_id)
{
	u64 reg_addr;
	union rdma_grp_net_list_tbl net_list_tbl = {0};

	reg_addr = DSCH_RDMA_GRP_NET_LIST_TBL(net_id);
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

static bool grc_check_grpnode_is_init(struct nbl_core_dev_info *core_dev, u16 grp_id)
{
	u64 reg_addr;
	union rdma_spt_grp_list_tbl grp_list_tbl = {0};

	reg_addr = DSCH_RDMA_SPT_GRP_LIST_TBL(grp_id);
	grp_list_tbl.data[0] = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);
	if (grp_list_tbl.valid || grp_list_tbl.sst)
		return false;

	return true;
}

static void grc_disable_rdma_net(struct nbl_core_dev_info *core_dev,
				 u16 function_id, uint8_t vld)
{
	u64 reg_addr;
	union rdma_n2g_cfg_tbl n2g_map = {0};
	u32 *value;
	bool net_flush_comp = false;
	bool net_init_state = false;
	bool need_check_flush = true;
	bool need_check_init = true;
	u16 grp_id;
	bool grp_flag = false;
	u16 retry_count = 0;
	struct nbl_grc *grc = container_of(core_dev, struct nbl_grc, core_dev);

	/* 1) disable rdma_net_en */
	grc_clear_rdma_net_en(core_dev, function_id);

	do {
		mdelay(DSCH_RDMA_DISABLE_DELAY_TIME);
		if (need_check_flush) {
			net_flush_comp = grc_check_netnode_if_flush(core_dev, function_id);
			if (net_flush_comp)
				need_check_flush = false;
		}

		if (need_check_init) {
			net_init_state = grc_check_netnode_is_init(core_dev, function_id);
			if (net_init_state)
				need_check_init = false;
		}

		if (net_flush_comp && net_init_state)
			break;

		grc_pr_debug("rdma%u node not back to init(flush_comp=%u,init_state=%u),waiting..",
			     function_id, net_flush_comp, net_init_state);
		retry_count++;
	} while (retry_count < DSCH_RDMA_MAX_RETRY_COUNT);

	grc_pr_debug("clear n2g config for function=%u", function_id);
	/* 2) disable net2grp */
	reg_addr = RDMA_N2G_CFG_TBL(function_id);
	value = (u32 *)&n2g_map;
	*value = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);
	grp_id = n2g_map.grp_id;

	memset(&n2g_map, 0, sizeof(n2g_map));
	grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, *value);

	spin_lock(&grc->grp_list_lock);
	clear_bit(function_id, grc->grp_list[grp_id].net_id_list);
	grc->grp_list[grp_id].count--;
	spin_unlock(&grc->grp_list_lock);

	grp_flag = grc_grp_node_if_need_disable(grc, grp_id);
	if (grp_flag) {
		bool grp_init_state = false;

		do {
			grp_init_state = grc_check_grpnode_is_init(core_dev, grp_id);
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

static void grc_enable_dsch(struct nbl_core_dev_info *core_dev, u16 function_id,
			    u32 host_id, u16 dport_id, uint8_t vld)
{
	u64 reg_addr;
	union rdma_n2g_cfg_tbl n2g_map = {0};
	union rdma_g2p_cfg_tbl g2p_map = { 0 };
	union rdma_tc_spwrr_cfg_tbl tc_spwrr_map = {0};
	union rdma_net2sha_map_tbl n2s_map = {0};
	union rdma_grp2sha_map_tbl g2s_map = {0};
	union rdma_sha2net_map_tbl s2n_map = {0};
	union rdma_sha2grp_map_tbl s2g_map = {0};
	u32 *value;
	struct grc_dsch_spec *dsch_spec = grc_get_dsch_spec();
	struct nbl_grc *grc = container_of(core_dev, struct nbl_grc, core_dev);

	grc_pr_debug(
		"enable rdma dsch regs for function_id=%u,host_id=%u,dport=%u,vld=%u\n",
		function_id, host_id, dport_id, vld);

	/* 1) enable grp2port */
	reg_addr = RDMA_G2P_CFG_TBL(function_id);
	g2p_map.vld = vld;
	g2p_map.port = dport_id;
	g2p_map.cpu_type = (host_id == HOST_ID_TYPE_ECPU ? 1 : 0);
	value = (u32 *)&g2p_map;
	grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, *value);

	/* 2) enable net2grp */
	reg_addr = RDMA_N2G_CFG_TBL(function_id);
	n2g_map.vld = vld;
	n2g_map.grp_id = function_id;
	value = (u32 *)&n2g_map;
	grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, *value);

	/* 3) enable rdma_net_en */
	spin_lock(&grc->grp_list_lock);
	set_bit(function_id, grc->grp_list[function_id].net_id_list);
	grc->grp_list[function_id].count++;
	spin_unlock(&grc->grp_list_lock);
	grc_set_rdma_net_en(core_dev, function_id);

	reg_addr = RDMA_TC_SPWRR_CFG_TBL(function_id);
	tc_spwrr_map.tc_spwrr = nbl_tm_algorithm_dwrr;
	value = (u32 *)&tc_spwrr_map;
	grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, *value);

	/* 4) enable sha2net,sha2grp */
	n2s_map.net_shaping_id = dsch_spec->min_net_shaping_id + function_id;
	reg_addr = RDMA_SHA2NET_MAP_TBL(n2s_map.net_shaping_id);
	s2n_map.vld = vld;
	s2n_map.rdma_vf_id = function_id;
	value = (u32 *)&s2n_map;
	grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, *value);

	g2s_map.grp_shaping_id =  dsch_spec->min_grp_shaping_id + function_id;
	reg_addr = RDMA_SHA2GRP_MAP_TBL(g2s_map.grp_shaping_id);
	s2g_map.vld = vld;
	s2g_map.rdma_grp_id = n2g_map.grp_id;
	value = (u32 *)&s2g_map;
	grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, *value);

	/* 5) enable net2sha,grp2sha */
	reg_addr = RDMA_NET2SHA_MAP_TBL(function_id);
	n2s_map.vld = vld;
	n2s_map.net_shaping_id = dsch_spec->min_net_shaping_id + function_id;
	value = (u32 *)&n2s_map;
	grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, *value);

	reg_addr = RDMA_GRP2SHA_MAP_TBL(function_id);
	g2s_map.vld = vld;
	g2s_map.grp_shaping_id =  dsch_spec->min_grp_shaping_id + function_id;
	value = (u32 *)&g2s_map;
	grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, *value);
}

static void grc_disable_dsch(struct nbl_core_dev_info *core_dev,
			     u16 function_id, u32 host_id, u16 dport_id,
			     uint8_t vld)
{
	u64 reg_addr;
	union rdma_n2g_cfg_tbl n2g_map = {0};
	union rdma_g2p_cfg_tbl g2p_map = {0};
	union rdma_tc_wgt_cfg_tbl tc_wgt_map = {0};
	union rdma_tc_spwrr_cfg_tbl tc_spwrr_map = {0};
	union rdma_net2sha_map_tbl n2s_map = {0};
	union rdma_grp2sha_map_tbl g2s_map = {0};
	union rdma_sha2net_map_tbl s2n_map = {0};
	union rdma_sha2grp_map_tbl s2g_map = {0};
	u32 *value;
	bool grp_flag;
	struct nbl_grc *grc = container_of(core_dev, struct nbl_grc, core_dev);

	grc_pr_debug(
		"disable rdma dsch regs for function_id=%u,host_id=%u,dport=%u,vld=%u\n",
		function_id, host_id, dport_id, vld);

	/* save n2p cfg before grc_disable_rdma_net */
	reg_addr = RDMA_N2G_CFG_TBL(function_id);
	value = (u32 *)&n2g_map;
	*value = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);

	grc_disable_rdma_net(core_dev, function_id, vld);

	reg_addr = RDMA_TC_WGT_CFG_TBL(function_id);
	value = &tc_wgt_map.data[0];
	grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, *value);
	value = &tc_wgt_map.data[1];
	grc_wr32(grc_cdev_to_hw_addr(core_dev) + 4, reg_addr, *value);

	reg_addr = RDMA_TC_SPWRR_CFG_TBL(function_id);
	tc_spwrr_map.tc_spwrr = nbl_tm_algorithm_dwrr;
	value = (u32 *)&tc_spwrr_map;
	grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, *value);

	/* 3) disable sha2net */
	reg_addr = RDMA_NET2SHA_MAP_TBL(function_id);
	value = (u32 *)&n2s_map;
	*value = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);

	reg_addr = RDMA_SHA2NET_MAP_TBL(n2s_map.net_shaping_id);
	value = (u32 *)&s2n_map;
	grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, *value);

	/* 4) disable net2sha */
	reg_addr = RDMA_NET2SHA_MAP_TBL(function_id);
	memset(&n2s_map, 0, sizeof(n2s_map));
	value = (u32 *)&n2s_map;
	grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, *value);

	/* 5) disable grp2port */
	reg_addr = RDMA_G2P_CFG_TBL(n2g_map.grp_id);
	value = (u32 *)&g2p_map;
	grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, *value);

	/* 6) disable sha2grp */
	reg_addr = RDMA_GRP2SHA_MAP_TBL(n2g_map.grp_id);
	value = (u32 *)&g2s_map;
	*value = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);

	reg_addr = RDMA_SHA2GRP_MAP_TBL(g2s_map.grp_shaping_id);
	value = (u32 *)&s2g_map;
	grp_flag = grc_grp_node_if_need_disable(grc, n2g_map.grp_id);
	if (!vld && grp_flag)
		grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, *value);

	/* 7) disable grp2sha */
	reg_addr = RDMA_GRP2SHA_MAP_TBL(n2g_map.grp_id);
	memset(&g2s_map, 0, sizeof(g2s_map));
	value = (u32 *)&g2s_map;
	grp_flag = grc_grp_node_if_need_disable(grc, n2g_map.grp_id);
	if (!vld && grp_flag)
		grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, *value);
}

static void grc_set_dsch_tbl(struct nbl_core_dev_info *core_dev,
			     u16 function_id, u32 host_id, u16 dport_id, u8 vld)
{
	if (vld)
		grc_enable_dsch(core_dev, function_id, host_id, dport_id, vld);
	else
		grc_disable_dsch(core_dev, function_id, host_id, dport_id, vld);

	grc_pr_debug("setting dsch regs end function_id=%u,host_id=%u,valid=%u\n",
		     function_id, host_id, vld);
}

static void nbl_update_rdma_dsch(struct nbl_core_dev_info *core_dev, u16 function_id,
				 u32 host_id, u16 dport_id, u8 vld)
{
	u64 reg_addr;
	union rdma_g2p_cfg_tbl g2p_map = {0};
	u32 *value;

	reg_addr = RDMA_G2P_CFG_TBL(function_id);
	g2p_map.vld = vld;
	g2p_map.cpu_type = (host_id == HOST_ID_TYPE_ECPU ? 1 : 0);
	g2p_map.port = dport_id;
	value = (u32 *)&g2p_map;
	grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, *value);
}

static void grc_set_cqp_info(struct nbl_core_dev_info *core_dev, u16 function_id,
			     u64 cqp_ba, u32 cqp_len, bool enable)
{
	u64 regs_addr;
	union nbl_cqp_info_tbl_reg cqp_info_tbl_reg = {0};

	grc_pr_debug("cqp_ba=0x%llx,cqp_len=%u,function_id=%u,valid=%s",
		     cqp_ba, cqp_len, function_id, enable ? "true" : "false");
	regs_addr = NBL_REG_CQPINFO_TBL_RAM_ADDR(function_id);
	if (enable) {
		cqp_info_tbl_reg.key.cqp_base_addr_high = (u32)(cqp_ba >> 32);
		cqp_info_tbl_reg.key.cqp_base_addr_low = (u32)cqp_ba;
		cqp_info_tbl_reg.key.cqp_len = (cqp_len & 0x3f);
		cqp_info_tbl_reg.key.cqp_pi_odd_even_flag = 0;
		cqp_info_tbl_reg.key.cqp_pi = 0;
		cqp_info_tbl_reg.key.cqp_info_vld = 1;
		cqp_info_tbl_reg.key.cqp_ci_odd_even_flag = 0;
		cqp_info_tbl_reg.key.cqp_ci = 0;

		/* as hardware need write valid at last, so here write cqp len/valid last */
		grc_wr32(grc_cdev_to_hw_addr(core_dev), regs_addr + 16, cqp_info_tbl_reg.data[4]);
		grc_wr32(grc_cdev_to_hw_addr(core_dev), regs_addr + 12, cqp_info_tbl_reg.data[3]);
		grc_wr32(grc_cdev_to_hw_addr(core_dev), regs_addr + 4, cqp_info_tbl_reg.data[1]);
		grc_wr32(grc_cdev_to_hw_addr(core_dev), regs_addr, cqp_info_tbl_reg.data[0]);
		grc_wr32(grc_cdev_to_hw_addr(core_dev), regs_addr + 8, cqp_info_tbl_reg.data[2]);
	} else {
		cqp_info_tbl_reg.key.cqp_len = (cqp_len & 0x3f);
		cqp_info_tbl_reg.key.cqp_info_vld = 0;
		/* when disable cqp, only valid bit need clear */
		grc_wr32(grc_cdev_to_hw_addr(core_dev), regs_addr + 8, cqp_info_tbl_reg.data[2]);
	}
}

static void grc_set_cqp_base_reg(struct nbl_core_dev_info *core_dev, u16 max_vfid)
{
	u64 regs_addr = NBL_REG_CQPP_MAX_FUN_ID;
	union nbl_cqp_max_fun_id_reg max_fun_id_reg = {0};

	/* Write CQP max fun id reg */
	max_fun_id_reg.key.max_fun_id = max_vfid;
	max_fun_id_reg.key.max_fun_id_vld = 1;
	grc_wr32(grc_cdev_to_hw_addr(core_dev), regs_addr, max_fun_id_reg.data);
	grc_pr_debug("write max fun id reg addr 0x%llx, val 0x%x\n",
		     regs_addr, max_fun_id_reg.data);

	/* Write CQP timeout count */
	regs_addr = NBL_REG_CQPP_TIMEOUT_CNT;
	grc_wr32(grc_cdev_to_hw_addr(core_dev), regs_addr,
		 (NBL_RDMA_CQP_HW_TIMEOUT * NBL_RDMA_SYS_CLK * NBL_RDMA_CQP_CLK_MULTIPLY));
	grc_pr_debug("write cqp timeout cnt reg addr 0x%llx, val 0x%x\n", regs_addr,
		     (NBL_RDMA_CQP_HW_TIMEOUT * NBL_RDMA_SYS_CLK * NBL_RDMA_CQP_CLK_MULTIPLY));
}

static void grc_set_cqp_pi(struct nbl_core_dev_info *core_dev, u32 cur_pi, u8 odd_even)
{
	u64 regs_addr;
	union nbl_cqp_info_tbl_reg cqp_info_tbl_reg = {0};

	cqp_info_tbl_reg.key.cqp_pi = cur_pi;
	cqp_info_tbl_reg.key.cqp_pi_odd_even_flag = odd_even;
	regs_addr = NBL_REG_CQPINFO_TBL_RAM_ADDR(NBL_RDMA_ADMIN_CQP_FUNCTION_NUM);
	grc_wr32(grc_cdev_to_hw_addr(core_dev), regs_addr + (NBL_REG_CQPINFO_PI_INDEX * 4),
		 cqp_info_tbl_reg.data[NBL_REG_CQPINFO_PI_INDEX]);
	grc_pr_debug("write cqp info table reg addr 0x%llx, val 0x%x\n",
		     (regs_addr + (NBL_REG_CQPINFO_PI_INDEX * 4)),
		     cqp_info_tbl_reg.data[NBL_REG_CQPINFO_PI_INDEX]);
}

static void grc_set_src_addr_info(struct nbl_core_dev_info *core_dev, u8 *smac, u8 *sip,
				  u8 insert_vlan_ipv4_valid, u16 src_addr_index)
{
	u64 src_addr_tbl_regs_addr = NBL_REG_SRC_ADDR_TBL_BASE;
	u64 reg_addr;
	union nbl_src_addr_info_tbl_reg info_tbl_reg = {0};
	u32 write_num;
	int i, j;

	/* for srcmac of key, byte0 corresponds to low-order information,
	 * and byte5 corresponds to high-order information
	 */
	for (i = 0; i < NBL_SRC_MAC_SIZE; i++)
		info_tbl_reg.key.smac[i] = smac[NBL_SRC_MAC_SIZE - 1 - i];

	/* for sip of key, byte0 corresponds to low-order information,
	 * and byte15 corresponds to high-order information
	 */
	for (j = 0; j < NBL_SRC_IP_SIZE; j++)
		info_tbl_reg.key.sip[j] = sip[NBL_SRC_IP_SIZE - 1 - j];

	info_tbl_reg.key.ipv4_valid = (insert_vlan_ipv4_valid & NBL_REG_IPV4_VALID);
	info_tbl_reg.key.vlan_vlaid = (insert_vlan_ipv4_valid & NBL_REG_VLAN_TAG);

	reg_addr = src_addr_tbl_regs_addr + NBL_SRC_ADDR_INFO_ENTRY_SIZE * src_addr_index;
	write_num = SRC_ADDR_INFO_TBL_KEY_REG_DW_SIZE;

	while (write_num--) {
		grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr + (write_num * 4),
			 info_tbl_reg.data[write_num]);
		grc_pr_debug("write src addr info table reg addr 0x%llx, val 0x%x\n",
			     (reg_addr + (write_num * 4)), info_tbl_reg.data[write_num]);
	};
}

static void grc_set_eot_table(struct nbl_core_dev_info *core_dev, bool valid)
{
	int depth = ARRAY_SIZE(hw_err_table);
	union nbl_eot_table_reg eot_reg = {0};
	u64 reg_addr;
	int ix;

	if (valid) {
		for (ix = 0; ix < depth; ix++) {
			memset(&eot_reg, 0, sizeof(eot_reg));

			eot_reg.key.ae_flag = hw_err_table[ix].ae ? 1 : 0;
			eot_reg.key.abnorm_cqe_flag = hw_err_table[ix].abnormal_cqe ? 1 : 0;
			eot_reg.key.norm_cqe_flag = hw_err_table[ix].normal_cqe ? 1 : 0;
			eot_reg.key.drop_flag = hw_err_table[ix].drop ? 1 : 0;

			reg_addr = NBL_REG_EOT_TBL_ADDR(ix);
			grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, eot_reg.data[0]);
			grc_pr_debug("set eot table(init):index %d, reg offset:0x%x, val: 0x%x\n",
				     ix, NBL_REG_EOT_TBL_ADDR(ix), eot_reg.data[0]);
		}
	} else {
		memset(&eot_reg, 0, sizeof(eot_reg));
		for (ix = 0; ix < depth; ix++) {
			reg_addr = NBL_REG_EOT_TBL_ADDR(ix);
			grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, eot_reg.data[0]);
			grc_pr_debug("eot table(deinit):index %d, reg offset:0x%x, val: 0x%x\n",
				     ix, NBL_REG_EOT_TBL_ADDR(ix), eot_reg.data[0]);
		}
	}
}

static void grc_set_hw_stat(struct nbl_core_dev_info *core_dev, u32 op_info)
{
	u64 reg_addr;

	reg_addr = NBL_RDMA_STATS_OP_INFO;
	grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, op_info);
	grc_pr_debug("reg_addr:0x%llx, op_info:[0x%x:0x%x]\n",
		      reg_addr, NBL_RDMA_STATS_OP_INFO, op_info);
}

static void grc_get_hw_stat(struct nbl_core_dev_info *core_dev, u32 op_info,
			    u32 pa_l, u32 pa_h, u16 func_id)
{
	grc_pr_debug("func_id:%d, info[0x%x:0x%x]\n", func_id, NBL_RDMA_STATS_OP_INFO, op_info);
	grc_pr_debug("pa_h[0x%x:0x%x], pa_l[0x%x:0x%x]\n",
		     NBL_RDMA_STATS_OP_DMA_ADDR_H, pa_h,
		     NBL_RDMA_STATS_OP_DMA_ADDR_L, pa_l);

	grc_wr32(grc_cdev_to_hw_addr(core_dev), NBL_RDMA_STATS_FUNC_ID, func_id);
	grc_wr32(grc_cdev_to_hw_addr(core_dev), NBL_RDMA_STATS_OP_DMA_ADDR_L, pa_l);
	grc_wr32(grc_cdev_to_hw_addr(core_dev), NBL_RDMA_STATS_OP_DMA_ADDR_H, pa_h);
	grc_wr32(grc_cdev_to_hw_addr(core_dev), NBL_RDMA_STATS_OP_INFO, op_info);
}

static void grc_enable_errcode_hw_stat(struct nbl_core_dev_info *core_dev,
				       u32 enable)
{
	grc_wr32(grc_cdev_to_hw_addr(core_dev), NBL_RDMA_STATS_OP_ERR_OPCODE_EN, enable);
	grc_pr_debug("offset:[0x%x:0x%x]\n", NBL_RDMA_STATS_OP_ERR_OPCODE_EN, enable);
}

static void grc_get_hw_status(struct nbl_core_dev_info *core_dev, u32 *status)
{
	void *reg_addr;

	reg_addr = core_dev->hw_addr + NBL_RDMA_STATS_OP_INFO;
	*status = readl(reg_addr);
	grc_pr_debug("reg_addr:%p, status:[0x%x:0x%x]\n",
		     reg_addr, NBL_RDMA_STATS_OP_INFO, *status);
}

static void nbl_set_rdma_pfid_map_tbl(struct nbl_core_dev_info *core_dev, u16 idx,
				      union nbl_rdma_pfid_map_tbl_reg *map)
{
	u64 reg_addr;
	u16 i = 0;

	reg_addr = NBL_PCOMP_HOST_RDMA_PFID_MAP_TABLE(idx);

	while (i < RDMA_PFID_MAP_TBL_KEY_REG_DW_SIZE) {
		grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr + (i * 4), map->data[i]);
		i++;
	};
}

static void nbl_set_rdma_tbl_sel(struct nbl_core_dev_info *core_dev, u16 sel)
{
	u32 *value;
	union nbl_rdma_tbl_sel_reg rdma_sel = {0};

	rdma_sel.rdma_tbl_sel = sel;
	value = (u32 *)&rdma_sel;
	grc_wr32(grc_cdev_to_hw_addr(core_dev), NBL_PCOMP_HOST_RDMA_TBL_SEL, *value);
}

static void nbl_set_rdma_tbl_ready(struct nbl_core_dev_info *core_dev, u16 ready)
{
	u32 *value;
	union nbl_rdma_tbl_ready_reg rdma_ready = {0};

	rdma_ready.rdma_tbl_ready = ready;
	value = (u32 *)&rdma_ready;
	grc_wr32(grc_cdev_to_hw_addr(core_dev), NBL_PCOMP_HOST_RDMA_TBL_READY, *value);
}

static u32 nbl_ib_get_reg_offset_addr(u32 offset)
{
	switch (offset) {
	case NBL_CFG_CC_EN:
		return NBL_REG_CC_EN;
	case NBL_CFG_CC_HIGH_RTT_FRACTION:
	case NBL_CFG_CC_LOW_RTT_FRACTION:
	case NBL_CFG_CC_HIGH_RTT_INT:
	case NBL_CFG_CC_LOW_RTT_INT:
		return NBL_REG_CC_RTTMINTH_COE;
	case NBL_CFG_CC_INC_TARWINTH:
		return NBL_REG_CC_INC_TARGET_WIN_TH;
	case NBL_CFG_CC_DEC_TARWINTH:
		return NBL_REG_CC_DEC_TARGET_WIN_TH;
	case NBL_CFG_CC_TXP_SENDREQ_DB_CFG:
		return NBL_REG_CC_TXP_SENDREQ_DB_CFG;
	case NBL_CFG_QCN_RR_MODE:
		return NBL_REG_QCN_RR_MODE;
	case NBL_CFG_QCN_MID_SENDBLK_TH_HIGH:
		return NBL_REG_QCN_MID_SENDBLK_TH_HIGH;
	case NBL_CFG_QCN_MID_SENDBLK_TH_LOW:
		return NBL_REG_QCN_MID_SENDBLK_TH_LOW;
	case NBL_CFG_QCN_MID_SENDTIME_TH_HIGH:
		return NBL_REG_QCN_MID_SENDTIME_TH_HIGH;
	case NBL_CFG_QCN_MID_SENDTIME_TH_LOW:
		return NBL_REG_QCN_MID_SENDTIME_TH_LOW;
	case NBL_CFG_QCN_RR_TH:
		return NBL_REG_QCN_RR_TH;
	case NBL_CFG_QCN_AI_RP:
		return NBL_REG_QCN_AI_RP;
	case NBL_CFG_QCN_HAI_RP:
		return NBL_REG_QCN_HAI_RP;
	case NBL_CFG_QCN_MIN_RATE_RP:
		return NBL_REG_QCN_MIN_RATE_RP;
	case NBL_CFG_QCN_MAX_RATE_RP:
		return NBL_REG_QCN_MAX_RATE_RP;
	case NBL_CFG_QCN_QUICK_START_FLAG:
		return NBL_REG_QCN_QUICK_START_FLAG;
	case NBL_CFG_QCN_SENDCNP_FLAG:
		return NBL_REG_QCN_SENDCNP_FLAG;
	case NBL_CFG_QCN_SENDCNP_TIME_TH:
		return NBL_REG_QCN_SENDCNP_TIME_TH;
	case NBL_CFG_QCN_EXTRA_QUANTA:
		return NBL_REG_QCN_EXTRA_QUANTA;
	case NBL_CFG_QCN_FAST_REDUCE_MODE:
		return NBL_REG_QCN_FAST_REDUCE_MODE;
	case NBL_CFG_QCN_REDUCE_COE:
		return NBL_REG_QCN_REDUCE_COE;
	case NBL_CFG_CC_RTT_OFFSET:
		return NBL_REG_CC_RTT_OFFSET;
	case NBL_CFG_CC_RTT_PROBE_INVL:
		return NBL_REG_CC_RTT_PROBE_INVL;
	case NBL_CFG_CC_HIGH_PRI_RTT_INVL:
		return NBL_REG_CC_HIGH_PRI_RTT_INVL;
	case NBL_CFG_CC_HIGH_PRI_RTT_EN:
		return NBL_REG_CC_HIGH_RPI_RTT_EN;
	case NBL_CFG_CC_RST_WIN_HIGH:
		return NBL_REG_CC_RST_WIN_H;
	case NBL_CFG_CC_RST_WIN_EN:
		return NBL_REG_CC_RST_WIN_EN;
	case NBL_CFG_CC_RST_WIN_LOW:
		return NBL_REG_CC_RST_WIN_L;
	case NBL_CFG_CC_RST_WIN_RTT_INT:
	case NBL_CFG_CC_RST_WIN_RTT_FRACTION:
		return NBL_REG_CC_RST_TARGETWIN_RTTCOE;
	case NBL_CFG_CC_DYN_RTT_OFFSET_EN:
		return NBL_REG_CC_DYN_RTT_OFFET_EN;
	case NBL_CFG_CC_REMOVE_REMOTE_TIME:
		return NBL_REG_CC_REMOVE_REMOTE_TIME;
	case NBL_CFG_CC_RDMA_TIME_SEL:
		return NBL_REG_CC_RDMA_TIME_SEL;
	case NBL_CFG_CC_LOW_RTT_OFFSET:
		return NBL_REG_CC_AI_LESS_RTTMINTH;
	case NBL_CFG_CC_HIGH_RTT_OFFSET:
		return NBL_REG_CC_AI_MORE_RTTMINTH;
	case NBL_CFG_CC_RST_WIN_RTT_OFFSET:
		return NBL_REG_CC_AI_RST_WIN_RTTMINTH;
	default:
		return 0;
	}
}

static void grc_set_cc_params(struct nbl_core_dev_info *core_dev,
			      u32 offset, u32 var)
{
	u64 reg_addr;
	u32 offset_addr;
	u32 var_old;
	u32 tmp_addr;
	u32 tmp_offset;
	u32 tmp_var;

	offset_addr = nbl_ib_get_reg_offset_addr(offset);
	if (offset_addr == 0) {
		grc_pr_err("get reg addr failed, cc param offset:%d var:%u\n", offset, var);
		return;
	}

	reg_addr = offset_addr;
	switch (offset) {
	case NBL_CFG_CC_EN:
		tmp_offset = nbl_ib_get_reg_offset_addr(NBL_CFG_CC_TXP_SENDREQ_DB_CFG);
		if (tmp_offset == 0) {
			grc_pr_err("tmp_offset:%u\n", tmp_offset);
			return;
		}
		tmp_addr = tmp_offset;
		var_old = grc_rd32(grc_cdev_to_hw_addr(core_dev), tmp_addr);
		tmp_var = (var_old & 0x7FFFFFFF) | ((var << 31) & 0x80000000);
		grc_wr32(grc_cdev_to_hw_addr(core_dev), tmp_addr, tmp_var);
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

	grc_wr32(grc_cdev_to_hw_addr(core_dev), offset_addr, var);
	grc_pr_debug("reg_addr:0x%llx, offset:%u var:%u\n", reg_addr, offset, var);
}

static void grc_set_vf_enable(struct nbl_core_dev_info *core_dev, u16 function_id, u8 enable)
{
	u64 reg_addr;
	u32 value;
	u16 index;

	index = function_id % HDMA_VF_ENABLE_SIZE;

	reg_addr = HDMA_VF_ENABLE + 4 * (function_id / HDMA_VF_ENABLE_SIZE);

	value = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);
	grc_pr_debug("set vf enable,function_id=%u,enable=%u\n", function_id, enable);

	if (enable) {
		value |= BIT(index);
		grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, value);

		reg_addr = HDMA_VF_CLEAR + 4 * (function_id / HDMA_VF_CLEAR_SIZE);

		value = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);
		value |= BIT(index);
		grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, value);
	} else {
		value &= ~BIT(index);
		grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, value);
	}
}

static void grc_set_hdma_dif_vfid(struct nbl_core_dev_info *core_dev, u16 function_id)
{
	u64 reg_addr = NBL_RDMA_TOP_HDMA_DIF_VFID;
	u32 value = function_id;

	grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, value);
}

static void grc_set_epro_cfg_err(struct nbl_core_dev_info *core_dev, u8 mask)
{
	u64 reg_addr;
	u32 value;

	reg_addr = EPRO_INT_MASK;
	value = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);
	if (mask)
		value |= BIT(EPRO_INT_MASK_CFG_ERR);
	else
		value &= ~BIT(EPRO_INT_MASK_CFG_ERR);

	grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, value);
}

static void grc_set_sw_db_wqe_cap(struct nbl_core_dev_info *core_dev)
{
	u64 reg_addr;
	union txp_sw_db_wqe_cap sw_wqe_cap = {0};

	reg_addr = SW_DB_WQE_CAP;
	sw_wqe_cap.data[0] = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);

	sw_wqe_cap.sw_db_wqe_cap = 1;
	grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, sw_wqe_cap.data[0]);
}

static void grc_init_net_tc_tbl(struct nbl_core_dev_info *core_dev)
{
	u64 reg_addr;

	reg_addr = NBL_REG_NET_TC_TBL_BASE;

	grc_wr32(grc_cdev_to_hw_addr(core_dev), (reg_addr + 0x00), 0x0);
	grc_wr32(grc_cdev_to_hw_addr(core_dev), (reg_addr + 0x04), 0x120);
	grc_wr32(grc_cdev_to_hw_addr(core_dev), (reg_addr + 0x08), 0x240);
	grc_wr32(grc_cdev_to_hw_addr(core_dev), (reg_addr + 0x0C), 0x360);
	grc_wr32(grc_cdev_to_hw_addr(core_dev), (reg_addr + 0x10), 0x480);
	grc_wr32(grc_cdev_to_hw_addr(core_dev), (reg_addr + 0x14), 0x5A0);
	grc_wr32(grc_cdev_to_hw_addr(core_dev), (reg_addr + 0x18), 0x6C0);
	grc_wr32(grc_cdev_to_hw_addr(core_dev), (reg_addr + 0x1C), 0x7E0);
}

static void nbl_set_vfid_vsi_map(struct nbl_core_dev_info *core_dev,
				 u16 function_id, u16 vsi_id, u8 valid)
{
	u64 reg_addr;
	union uqm_vsi_vfid_map_tbl vsi_map = {0};
	u16 index;
	u32 vsi_btm_value;

	vsi_map.vf_id = function_id;
	vsi_map.valid = valid;

	reg_addr = UQM_VSI_MAPPING_TBL(vsi_id);
	grc_pr_debug("UQM_VSI_MAPPING_TBL addr=0x%llx for vsi_id=%u\n", reg_addr, vsi_id);
	grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, vsi_map.data[0]);

	index = vsi_id % PP_RDMA_VSI_BTM_ENTRY_SZ;
	reg_addr = PP_RDMA_VSI_BTM + 4 * (vsi_id / PP_RDMA_VSI_BTM_ENTRY_SZ);
	grc_pr_debug("PP_RDMA_VSI_BTM addr=0x%llx for vsi_id=%u\n", reg_addr, vsi_id);
	vsi_btm_value = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);
	if (valid)
		vsi_btm_value |= BIT(index);
	else
		vsi_btm_value &= ~BIT(index);

	grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, vsi_btm_value);
}

static void nbl_enable_rdma_intrl(struct nbl_core_dev_info *core_dev, u16 global_msix_idx,
				  u8 devfn, u8 bus, u8 valid)
{
	u64 reg_addr;
	u32 reg_val;
	union padapt_host_msix_info msix_info_tbl = {0};

	msix_info_tbl.bus_id = bus;
	msix_info_tbl.device_id = devfn >> 3;
	msix_info_tbl.function_id = devfn & 0x7;
	msix_info_tbl.intrl_pnum = 0;
	msix_info_tbl.intrl_rate = 0;
	msix_info_tbl.valid = valid ? 1 : 0;

	reg_addr = HOST_MSIX_INFO_TBL(global_msix_idx);
	grc_write_regs(grc_cdev_to_hw_addr(core_dev), reg_addr,
		       msix_info_tbl.data, ARRAY_SIZE(msix_info_tbl.data));

	reg_addr = HOST_MSIX_CTRL_TBL(global_msix_idx) + 12;
	reg_val = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);
	if (valid)
		reg_val &= ~BIT(0);
	else
		reg_val |= BIT(0);

	grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, reg_val);
}

static char *rdma_interrupt_module[] = {
	"resv",
	"cqpp",
	"hdma",
	"txp",
	"txmr",
	"txm",
	"rxp",
	"rxmr",
	"rxm",
	"raqp",
	"ceaq",
	"prob",
	"adpt",
	"qpcc",
	"cqcc",
	"mrtc",
	"pblc",
	"cc",
	"sqrqec",
	"irqec",
	"orqec",
	"unapec",
	"raqec",
	"tqp",
	"resv",
	"stat"
};

static void grc_get_rdma_abnormal_event(struct nbl_core_dev_info *core_dev)
{
	u64 reg_addr;
	u32 value;
	u32 sub_module_int;
	int i = 0;
	DECLARE_BITMAP(ab_events, NBL_RDMA_MAX_MODULES);
	u32 other_abn;
	u8 err_id;

	reg_addr = RDMA_DSCH_BASE;
	value = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);
	other_abn = grc_rd32(grc_cdev_to_hw_addr(core_dev), DSCH_RDMA_OTHER_ABN_INFO);
	/* mask dsch in grc, avoid print dsch abnormal event in kernel_driver */
	if (value & DSCH_RDMA_OTHER_ABN) {
		grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, (value & DSCH_RDMA_OTHER_ABN));
		err_id = other_abn & DSCH_RDMA_OTHER_ABN_INFO_MASK;
		if (err_id != DSCH_RDMA_SW_DB_FULL)
			grc_pr_notice(
				"[rdma][dsch] rdma_other_abn=%#x,other_abn_info=%#x\n",
				value, other_abn);
	}

	reg_addr = NBL_REG_RDMA_TOP;
	value = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);
	ab_events[0] = value;
	i = (int)find_next_bit(ab_events, NBL_RDMA_MAX_MODULES, i);
	while (i < NBL_RDMA_MAX_MODULES) {
		reg_addr = NBL_REG_RDMA_TOP + (i << RDMA_SUBMODULE_BASE_SHIFT);
		sub_module_int = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);

		grc_pr_notice("[rdma][submodule_%s] generated event=%#x\n",
			      rdma_interrupt_module[i], sub_module_int);

		grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, sub_module_int);
		i = (int)find_next_bit(ab_events, NBL_RDMA_MAX_MODULES, i + 1);
		grc_pr_debug("3.rdma submodule idx=%d\n", i);
	}
}

static void grc_set_rqdb_int_mask(struct nbl_core_dev_info *core_dev)
{
	u64 reg_addr = NBL_REG_CQPP_INTRRUPT_MASK;
	u32 value;

	value = grc_rd32(grc_cdev_to_hw_addr(core_dev), reg_addr);

	value |= NBL_RQDB_DROP_INT_MASK;
	grc_wr32(grc_cdev_to_hw_addr(core_dev), reg_addr, value);
}

static void grc_set_qos_default_cfg(struct nbl_core_dev_info *core_dev)
{
	grc_wr32(grc_cdev_to_hw_addr(core_dev), NBL_REG_DSCH_SQ_PRI_MAP_CFG,
		 NBL_QOS_DEFAULT_SQ_PRI_MAP);
	grc_wr32(grc_cdev_to_hw_addr(core_dev), NBL_REG_DSCH_RAQ_PRI_MAP_CFG,
		 NBL_QOS_DEFAULT_RAQ_PRI_MAP);
	grc_wr32(grc_cdev_to_hw_addr(core_dev), NBL_REG_DSCH_IMAP_CFG,
		 NBL_QOS_DEFAULT_PRI_IMAP);
	grc_wr32(grc_cdev_to_hw_addr(core_dev), NBL_REG_DSCH_PRI03_MAP_CFG,
		 NBL_QOS_DEFAULT_PFC03_MAP);
	grc_wr32(grc_cdev_to_hw_addr(core_dev), NBL_REG_DSCH_PRI47_MAP_CFG,
		 NBL_QOS_DEFAULT_PFC47_MAP);

	grc_wr32(grc_cdev_to_hw_addr(core_dev), NBL_REG_DSCH_CSCH_QLEN_TH,
		 NBL_QOS_DEFAULT_CSCH_QLEN_TH);
	grc_wr32(grc_cdev_to_hw_addr(core_dev), NBL_REG_DSCH_POLL_WGT,
		 NBL_QOS_DEFAULT_POLL_WGT);
	grc_wr32(grc_cdev_to_hw_addr(core_dev), NBL_REG_DSCH_SW_DB_IN_CSCH_TH,
		 NBL_QOS_DEFAULT_SW_DB_IN_CSCH_TH);
}

static void grc_set_dif_vf_off(struct nbl_core_dev_info *core_dev, bool is_off)
{
	u32 val =
		grc_rd32(grc_cdev_to_hw_addr(core_dev), RDMA_REG_HDMA_CPU_CTRL);
	if (is_off)
		val |= RDMA_HDMA_DIF_VF_EN;
	else
		val &= ~RDMA_HDMA_DIF_VF_EN;
	grc_pr_debug("dif_vf_en:%#x\n", val);
	grc_wr32(grc_cdev_to_hw_addr(core_dev), RDMA_REG_HDMA_CPU_CTRL, val);
}

struct grc_hw_cache_info {
	u32 cache_type;
	u32 cache_low_th_addr;
	u32 cache_high_th_addr;
	u32 cache_depth;
};

static struct grc_hw_cache_info hw_cache[] = {
	{ NBL_CACHE_QPCC, NBL_REG_QPC_IDLE_BLOCK_FIFO_THR_LOW,
		NBL_REG_QPC_IDLE_BLOCK_FIFO_THR_HIGH, NBL_REG_QPC_CACHE_DEPTH },
	{ NBL_CACHE_CQCC, NBL_REG_CQC_IDLE_BLOCK_FIFO_THR_LOW,
		NBL_REG_CQC_IDLE_BLOCK_FIFO_THR_HIGH, NBL_REG_CQC_CACHE_DEPTH },
	{ NBL_CACHE_MRTC, NBL_REG_MRTE_IDLE_BLOCK_FIFO_THR_LOW,
		NBL_REG_MRTE_IDLE_BLOCK_FIFO_THR_HIGH, NBL_REG_MRTE_CACHE_DEPTH },
	{ NBL_CACHE_SQRQEC, NBL_REG_SQRQE_IDLE_BLOCK_FIFO_THR_LOW,
		NBL_REG_SQRQE_IDLE_BLOCK_FIFO_THR_HIGH, NBL_REG_SQRQE_CACHE_DEPTH }
};

static void grc_clear_hw_cache(struct nbl_core_dev_info *core_dev, u32 cache_type)
{
	int i;
	u32 fifo_thr_high;
	u32 fifo_thr_low;

	for (i = 0; i < ARRAY_SIZE(hw_cache); i++) {
		if (hw_cache[i].cache_type == cache_type) {
			fifo_thr_high = grc_rd32(grc_cdev_to_hw_addr(core_dev),
						 hw_cache[i].cache_high_th_addr);
			fifo_thr_low = grc_rd32(grc_cdev_to_hw_addr(core_dev),
						hw_cache[i].cache_low_th_addr);
			grc_wr32(grc_cdev_to_hw_addr(core_dev), hw_cache[i].cache_high_th_addr,
				 hw_cache[i].cache_depth);
			grc_wr32(grc_cdev_to_hw_addr(core_dev), hw_cache[i].cache_low_th_addr,
				 hw_cache[i].cache_depth);
			grc_wr32(grc_cdev_to_hw_addr(core_dev), hw_cache[i].cache_high_th_addr,
				 fifo_thr_high);
			grc_wr32(grc_cdev_to_hw_addr(core_dev), hw_cache[i].cache_low_th_addr,
				 fifo_thr_low);
			return;
		}
	}
}

struct nbl_hw_rdma_ops hw_rdma_ops = {
	.set_sd_range = grc_set_sd_range,
	.get_sd_range = __grc_get_sd_range,
	.set_bdf_func_id_map = grc_set_bdf_func_id_map,
	.set_rdma_dsch = grc_set_dsch_tbl,
	.set_cqp_info = grc_set_cqp_info,
	.set_cqp_base_reg = grc_set_cqp_base_reg,
	.set_cqp_pi = grc_set_cqp_pi,
	.set_src_addr_info = grc_set_src_addr_info,
	.set_eot_table = grc_set_eot_table,
	.set_hw_stat = grc_set_hw_stat,
	.get_hw_stat = grc_get_hw_stat,
	.enable_errcode_hw_stat = grc_enable_errcode_hw_stat,
	.get_hw_status = grc_get_hw_status,
	.set_rdma_pfid_map_tbl = nbl_set_rdma_pfid_map_tbl,
	.set_rdma_tbl_sel = nbl_set_rdma_tbl_sel,
	.set_rdma_tbl_ready = nbl_set_rdma_tbl_ready,
	.set_cc_params = grc_set_cc_params,
	.set_vf_enable = grc_set_vf_enable,
	.set_vfid_vsi_map = nbl_set_vfid_vsi_map,
	.ena_rdma_intrl = nbl_enable_rdma_intrl,
	.init_net_tc_tbl = grc_init_net_tc_tbl,
	.update_rdma_dsch = nbl_update_rdma_dsch,
	.set_epro_cfg_err = grc_set_epro_cfg_err,
	.set_hdma_dif_vfid = grc_set_hdma_dif_vfid,
	.get_abnormal_event = grc_get_rdma_abnormal_event,
	.set_rqdb_int_mask = grc_set_rqdb_int_mask,
	.set_qos_default_cfg = grc_set_qos_default_cfg,
	.set_dif_vf_off = grc_set_dif_vf_off,
	.set_sw_db_wqe_cap = grc_set_sw_db_wqe_cap,
	.clear_hw_cache = grc_clear_hw_cache,
};
