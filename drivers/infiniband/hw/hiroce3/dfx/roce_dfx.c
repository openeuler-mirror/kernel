// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#ifdef __ROCE_DFX__

#include <linux/fs.h>
#include <linux/slab.h>

#include "hinic3_mt.h"

#include "roce.h"
#include "roce_cmd.h"
#include "roce_pub_cmd.h"
#include "roce_dfx.h"


void roce3_dfx_clean_up(struct roce3_device *rdev)
{
#ifdef ROCE_PKT_CAP_EN
	(void)roce3_dfx_stop_cap_pkt(rdev, NULL, NULL);
#endif
}

int roce3_get_drv_version(struct roce3_device *rdev, const void *buf_in, u32 in_size,
	void *buf_out, u32 *out_size)
{
	struct drv_version_info *ver_info = buf_out;
	int rc;

	if (!buf_out) {
		pr_err("Buf_out is NULL.\n");
		return -EINVAL;
	}

	if (*out_size != sizeof(*ver_info)) {
		pr_err("Unexpect out buf size from user :%u, expect: %lu\n",
			*out_size, sizeof(*ver_info));
		return -EINVAL;
	}

	rc = snprintf(ver_info->ver, sizeof(ver_info->ver), "%s  %s",
		HIROCE3_DRV_VERSION, "2024-04-16_15:14:30");
	if (rc == -1) {
		pr_err("Snprintf roce version err\n");
		return -EFAULT;
	}

	return 0;
}

static int roce3_dfx_enable_bw_ctrl(struct roce3_device *rdev, struct roce3_bw_ctrl_inbuf *inbuf,
	struct roce3_bw_ctrl_outbuf *outbuf)
{
	if (rdev->hw_info.hca_type == ROCE3_2_100G_HCA) {
		inbuf->ctrl_param.cir = ROCE3_100G_CIR;
		inbuf->ctrl_param.pir = ROCE3_100G_PIR;
		inbuf->ctrl_param.cnp = ROCE3_100G_CNP;
	} else {
		inbuf->ctrl_param.cir = ROCE3_25G_CIR;
		inbuf->ctrl_param.pir = ROCE3_25G_PIR;
		inbuf->ctrl_param.cnp = ROCE3_25G_CNP;
	}
	return roce3_set_bw_ctrl_state(rdev, ROCE_BW_CTRL_EN, inbuf);
}

static int roce3_dfx_disable_bw_ctrl(struct roce3_device *rdev, struct roce3_bw_ctrl_inbuf *inbuf,
	struct roce3_bw_ctrl_outbuf *outbuf)
{
	inbuf->ctrl_param.cir = 0;
	inbuf->ctrl_param.pir = 0;
	inbuf->ctrl_param.cnp = 0;
	return roce3_set_bw_ctrl_state(rdev, ROCE_BW_CTRL_DIS, inbuf);
}

static int roce3_dfx_change_bw_ctrl_param(struct roce3_device *rdev,
	struct roce3_bw_ctrl_inbuf *inbuf, struct roce3_bw_ctrl_outbuf *outbuf)
{
	return roce3_set_bw_ctrl_state(rdev, ROCE_BW_CTRL_RESET, inbuf);
}

static int roce3_dfx_query_bw_ctrl_param(struct roce3_device *rdev,
	struct roce3_bw_ctrl_inbuf *inbuf, struct roce3_bw_ctrl_outbuf *outbuf)
{
	return roce3_query_bw_ctrl_state(rdev, &outbuf->bw_ctrl_param);
}

typedef int (*roce3_adm_dfx_bw_ctrl_func_t)(struct roce3_device *rdev,
	struct roce3_bw_ctrl_inbuf *inbuf, struct roce3_bw_ctrl_outbuf *outbuf);

/*lint -e26*/
static roce3_adm_dfx_bw_ctrl_func_t g_roce3_adm_dfx_bw_ctrl_funcs[COMMON_CMD_VM_COMPAT_TEST] = {
	[ROCE_CMD_ENABLE_BW_CTRL] = roce3_dfx_enable_bw_ctrl,
	[ROCE_CMD_DISABLE_BW_CTRL] = roce3_dfx_disable_bw_ctrl,
	[ROCE_CMD_CHANGE_BW_CTRL_PARAM] = roce3_dfx_change_bw_ctrl_param,
	[ROCE_CMD_QUERY_BW_CTRL_PARAM] = roce3_dfx_query_bw_ctrl_param,
};
/*lint +e26*/

int roce3_adm_dfx_bw_ctrl(struct roce3_device *rdev, const void *buf_in,
	u32 in_size, void *buf_out, u32 *out_size)
{
	struct roce3_bw_ctrl_inbuf *inbuf = (struct roce3_bw_ctrl_inbuf *)buf_in;
	struct roce3_bw_ctrl_outbuf *outbuf = (struct roce3_bw_ctrl_outbuf *)buf_out;
	roce3_adm_dfx_bw_ctrl_func_t roce3_adm_dfx_bw_ctrl_func;

	memset(buf_out, 0, sizeof(struct roce3_bw_ctrl_outbuf));
	*out_size = sizeof(struct roce3_bw_ctrl_outbuf);

	if (inbuf->cmd_type >= COMMON_CMD_VM_COMPAT_TEST) {
		dev_err(rdev->hwdev_hdl, "Not support this type(%d)\n", inbuf->cmd_type);
		return -EINVAL;
	}

	roce3_adm_dfx_bw_ctrl_func = g_roce3_adm_dfx_bw_ctrl_funcs[inbuf->cmd_type];
	if (roce3_adm_dfx_bw_ctrl_func == NULL) {
		dev_err(rdev->hwdev_hdl, "Not support this type(%d)\n", inbuf->cmd_type);
		return -EINVAL;
	}

	return roce3_adm_dfx_bw_ctrl_func(rdev, inbuf, outbuf);
}
#endif /* __ROCE_DFX__ */
