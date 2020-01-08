// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include "hns3_cae_cmd.h"

static int hns3_cae_ring_space(struct hclge_cmq_ring *ring)
{
	int ntu = ring->next_to_use;
	int ntc = ring->next_to_clean;
	int used = (ntu - ntc + ring->desc_num) % ring->desc_num;

	return ring->desc_num - used - 1;
}

static int is_valid_csq_clean_head(struct hclge_cmq_ring *ring, int head)
{
	int ntu = ring->next_to_use;
	int ntc = ring->next_to_clean;

	if (ntu > ntc)
		return head >= ntc && head <= ntu;

	return head >= ntc || head <= ntu;
}

static bool hns3_cae_is_special_opcode(u16 opcode)
{
	/* these commands have several descriptors,
	 * and use the first one to save opcode and return value
	 */
	u16 spec_opcode[] = {HCLGE_OPC_STATS_64_BIT,
			     HCLGE_OPC_STATS_32_BIT,
			     HCLGE_OPC_STATS_MAC,
			     HCLGE_OPC_STATS_MAC_ALL,
			     HCLGE_OPC_QUERY_32_BIT_REG,
			     HCLGE_OPC_QUERY_64_BIT_REG,
			     HCLGE_QUERY_CLEAR_MPF_RAS_INT,
			     HCLGE_QUERY_CLEAR_PF_RAS_INT,
			     HCLGE_QUERY_CLEAR_ALL_MPF_MSIX_INT,
			     HCLGE_QUERY_CLEAR_ALL_PF_MSIX_INT};
	u16 i;

	for (i = 0; i < ARRAY_SIZE(spec_opcode); i++) {
		if (spec_opcode[i] == opcode)
			return true;
	}

	return false;
}

static int hns3_cae_cmd_convert_err_code(u16 desc_ret)
{
	switch (desc_ret) {
	case HCLGE_CMD_EXEC_SUCCESS:
		return 0;
	case HCLGE_CMD_NO_AUTH:
		return -EPERM;
	case HCLGE_CMD_NOT_SUPPORTED:
		return -EOPNOTSUPP;
	case HCLGE_CMD_QUEUE_FULL:
		return -EXFULL;
	case HCLGE_CMD_NEXT_ERR:
		return -ENOSR;
	case HCLGE_CMD_UNEXE_ERR:
		return -ENOTBLK;
	case HCLGE_CMD_PARA_ERR:
		return -EINVAL;
	case HCLGE_CMD_RESULT_ERR:
		return -ERANGE;
	case HCLGE_CMD_TIMEOUT:
		return -ETIME;
	case HCLGE_CMD_HILINK_ERR:
		return -ENOLINK;
	case HCLGE_CMD_QUEUE_ILLEGAL:
		return -ENXIO;
	case HCLGE_CMD_INVALID:
		return -EBADR;
	default:
		return -EIO;
	}
}

static int hns3_cae_cmd_csq_done(struct hclge_hw *hw)
{
	u32 head = hclge_read_dev(hw, HCLGE_NIC_CSQ_HEAD_REG);

	return head == hw->cmq.csq.next_to_use;
}

static int hns3_cae_cmd_csq_clean(struct hclge_hw *hw)
{
	struct hclge_dev *hdev = container_of(hw, struct hclge_dev, hw);
	struct hclge_cmq_ring *csq = &hw->cmq.csq;
	int clean;
	u32 head;

	head = hclge_read_dev(hw, HCLGE_NIC_CSQ_HEAD_REG);
	rmb(); /* Make sure head is ready before touch any data */

	if (!is_valid_csq_clean_head(csq, head)) {
		dev_warn(&hdev->pdev->dev, "wrong cmd head (%u, %d-%d)\n", head,
			 csq->next_to_use, csq->next_to_clean);
		dev_warn(&hdev->pdev->dev,
			 "IMP firmware watchdog reset soon expected!\n");
		return -EIO;
	}

	clean = (head - csq->next_to_clean + csq->desc_num) % csq->desc_num;
	csq->next_to_clean = head;

	return clean;
}

static int hns3_cae_cmd_check_retval(struct hclge_hw *hw,
				     struct hclge_desc *desc,
				     int num, int ntc)
{
	u16 opcode, desc_ret;
	int handle;

	opcode = le16_to_cpu(desc[0].opcode);
	for (handle = 0; handle < num; handle++) {
		desc[handle] = hw->cmq.csq.desc[ntc];
		ntc++;
		if (ntc >= hw->cmq.csq.desc_num)
			ntc = 0;
	}
	if (likely(!hns3_cae_is_special_opcode(opcode)))
		desc_ret = le16_to_cpu(desc[num - 1].retval);
	else
		desc_ret = le16_to_cpu(desc[0].retval);

	hw->cmq.last_status = desc_ret;

	return hns3_cae_cmd_convert_err_code(desc_ret);
}

void hns3_cae_cmd_reuse_desc(struct hclge_desc *desc, bool is_read)
{
	desc->flag = cpu_to_le16(HCLGE_CMD_FLAG_NO_INTR | HCLGE_CMD_FLAG_IN);
	if (is_read)
		desc->flag |= cpu_to_le16(HCLGE_CMD_FLAG_WR);
	else
		desc->flag &= cpu_to_le16(~HCLGE_CMD_FLAG_WR);
}

void hns3_cae_cmd_setup_basic_desc(struct hclge_desc *desc,
				   enum hclge_opcode_type opcode, bool is_read)
{
	memset((void *)desc, 0, sizeof(struct hclge_desc));
	desc->opcode = cpu_to_le16(opcode);
	desc->flag = cpu_to_le16(HCLGE_CMD_FLAG_NO_INTR | HCLGE_CMD_FLAG_IN);

	if (is_read)
		desc->flag |= cpu_to_le16(HCLGE_CMD_FLAG_WR);
}

/**
 * hns3_cae_cmd_send - send command to command queue
 * @hdev: pointer to the hclge_dev
 * @desc: prefilled descriptor for describing the command
 * @num : the number of descriptors to be sent
 *
 * This is the main send command for command queue, it
 * sends the queue, cleans the queue, etc
 **/
int hns3_cae_cmd_send(struct hclge_dev *hdev, struct hclge_desc *desc, int num)
{
	struct hclge_desc *desc_to_use;
	struct hclge_cmq_ring *csq;
	bool complete = false;
	u32 timeout = 0;
	int handle = 0;
	int retval = 0;
	int ntc;

	csq = &hdev->hw.cmq.csq;
	spin_lock_bh(&hdev->hw.cmq.csq.lock);

	if (test_bit(HCLGE_STATE_CMD_DISABLE, &hdev->state)) {
		spin_unlock_bh(&hdev->hw.cmq.csq.lock);
		return -EBUSY;
	}

	if (num > hns3_cae_ring_space(&hdev->hw.cmq.csq)) {
		/* If CMDQ ring is full, SW HEAD and HW HEAD may be different,
		 * need update the SW HEAD pointer csq->next_to_clean
		 */
		csq->next_to_clean = hclge_read_dev(&hdev->hw,
						    HCLGE_NIC_CSQ_HEAD_REG);
		spin_unlock_bh(&hdev->hw.cmq.csq.lock);
		return -EBUSY;
	}

	/**
	 * Record the location of desc in the ring for this time
	 * which will be use for hardware to write back
	 */
	ntc = hdev->hw.cmq.csq.next_to_use;
	while (handle < num) {
		desc_to_use =
			&hdev->hw.cmq.csq.desc[hdev->hw.cmq.csq.next_to_use];
		*desc_to_use = desc[handle];
		(hdev->hw.cmq.csq.next_to_use)++;
		if (hdev->hw.cmq.csq.next_to_use >= hdev->hw.cmq.csq.desc_num)
			hdev->hw.cmq.csq.next_to_use = 0;
		handle++;
	}

	/* Write to hardware */
	hclge_write_dev(&hdev->hw, HCLGE_NIC_CSQ_TAIL_REG,
			hdev->hw.cmq.csq.next_to_use);

	/**
	 * If the command is sync, wait for the firmware to write back,
	 * if multi descriptors to be sent, use the first one to check
	 */
	if (HCLGE_SEND_SYNC(le16_to_cpu(desc->flag))) {
		do {
			if (hns3_cae_cmd_csq_done(&hdev->hw)) {
				complete = true;
				break;
			}
			udelay(1);
			timeout++;
		} while (timeout < hdev->hw.cmq.tx_timeout);
	}

	if (!complete)
		retval = -EBADE;
	else
		retval = hns3_cae_cmd_check_retval(&hdev->hw, desc, num, ntc);

	handle = hns3_cae_cmd_csq_clean(&hdev->hw);
	if (handle < 0)
		retval = handle;
	else if (handle != num)
		dev_warn(&hdev->pdev->dev,
			 "cleaned %d, need to clean %d\n", handle, num);

	spin_unlock_bh(&hdev->hw.cmq.csq.lock);

	return retval;
}

struct hclge_vport *hns3_cae_get_vport(struct hnae3_handle *handle)
{
	return container_of(handle, struct hclge_vport, nic);
}
