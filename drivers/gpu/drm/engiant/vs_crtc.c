// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 VeriSilicon Holdings Co., Ltd.
 *
 * Modified: 2025-03-17
 *   - Added egt_dp_source_video_state(ON) in vs_crtc_atomic_enable to
 *     fix black screen on resolution switch
 */

#include <drm/drm_atomic.h>
#include <drm/drm_vblank.h>

#include "vs_crtc.h"
#include "vs_gem.h"
#include "vs_dc.h"
#include "vs_dc_hw.h"
#include "vs_dc_property.h"
#include "vs_dc_drm_property.h"

bool vs_egt_display_get_crtc_scanoutpos(struct drm_device *dev, unsigned int crtc_id,
					bool in_vblank_irq, int *vpos, int *hpos, ktime_t *stime,
					ktime_t *etime, const struct drm_display_mode *mode)
{
	struct drm_crtc *crtc = drm_crtc_from_index(dev, crtc_id);
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);
	u32 position;
	int vblank_lines;
	bool ret = false;

	/*
	 * While in vblank, position will be negative counting up
	 * towards 0 at vbl_end. And outside vblank, position will
	 * be positive counting up since vbl_end.
	 */
	if (!in_vblank_irq) {
		/* Get optional system timestamp before query. */
		if (stime)
			*stime = ktime_get();

		if (!vs_crtc->funcs->get_crtc_scanout_position) {
			/*
			 * Return a vpos of zero, which will cause calling code
			 * to just return the etime timestamp uncorrected.
			 * At least this is no worse than the standard fallback.
			 */
			DRM_DEBUG("[CRTC:%d:%s] get_crtc_scanout_position() isn't implemented!\n",
				  crtc->base.id, crtc->name);
			*hpos = *vpos = 0;
		} else {
			ret = vs_crtc->funcs->get_crtc_scanout_position(vs_crtc->dev, crtc,
									&position);
			if (ret != 0)
				return false;

			/* Decode into vertical and horizontal scanout position. */
			*hpos = position & 0xffff;
			*vpos = (position >> 16) & 0xffff;
		}

		/* Get optional system timestamp after query. */
		if (etime)
			*etime = ktime_get();
	} else {
		vblank_lines = mode->vtotal - mode->vdisplay;
		/*
		 * Assume the irq handler got called close to first
		 * line of vblank, so HW has about a full vblank
		 * scanlines to go, and as a base timestamp use the
		 * one taken at entry into vblank irq handler, so it
		 * is not affected by random delays due to lock
		 * contention on event_lock or vblank_time lock in
		 * the core.
		 */
		*hpos = 0;
		*vpos = -vblank_lines;

		if (stime)
			*stime = vs_crtc->t_vblank;
		if (etime)
			*etime = vs_crtc->t_vblank;
	}

	return true;
}

void vs_egt_crtc_destroy(struct drm_crtc *crtc)
{
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);

	if (crtc->port)
		of_node_put(crtc->port);
	drm_crtc_cleanup(crtc);
	kfree(vs_crtc);
}

static void vs_crtc_reset(struct drm_crtc *crtc)
{
	struct vs_crtc_state *state;
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);
	u32 i;

	/*init the frame completion for CRTC */
	init_completion(&vs_crtc->frame_completion);
	complete(&vs_crtc->frame_completion);

	if (crtc->state) {
		__drm_atomic_helper_crtc_destroy_state(crtc->state);

		state = to_vs_crtc_state(crtc->state);
		drm_property_blob_put(state->prior_gamma);
		drm_property_blob_put(state->roi0_gamma);
		drm_property_blob_put(state->roi1_gamma);
#ifdef CONFIG_ENGIANT_VS_LTM
		drm_property_blob_put(state->ltm_luma_get);
		drm_property_blob_put(state->ltm_cd_get);
		drm_property_blob_put(state->ltm_hist_get);
#endif
#ifdef CONFIG_ENGIANT_VS_HISTOGRAM
		drm_property_blob_put(state->hist_get);
		drm_property_blob_put(state->rgb_hist_get);
#endif
		for (i = 0; i < vs_crtc->properties.num; i++) {
			if (state->drm_states[i].proto->type == VS_DC_PROPERTY_BLOB)
				drm_property_blob_put(state->drm_states[i].value.blob);
		}

		kfree(state);
		crtc->state = NULL;
	}

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return;

	__drm_atomic_helper_crtc_reset(crtc, &state->base);

	state->sync_mode = VS_EGT_SINGLE_DC;
	state->output_fmt = MEDIA_BUS_FMT_RGB888_1X24;
	state->encoder_type = DRM_MODE_ENCODER_NONE;
#ifdef CONFIG_ENGIANT_VS_MMU
	state->mmu_prefetch = VS_EGT_MMU_PREFETCH_DISABLE;
#endif

	vs_crtc->funcs->reset(vs_crtc);

	for (i = 0; i < vs_crtc->properties.num; i++)
		state->drm_states[i].proto = vs_crtc->properties.items[i].proto;
}

static void _vs_crtc_duplicate_blob(struct vs_crtc_state *state, struct vs_crtc_state *ori_state)
{
	state->prior_gamma = ori_state->prior_gamma;
	state->roi0_gamma = ori_state->roi0_gamma;
	state->roi1_gamma = ori_state->roi1_gamma;
#ifdef CONFIG_ENGIANT_VS_LTM
	state->ltm_luma_get = ori_state->ltm_luma_get;
	state->ltm_cd_get = ori_state->ltm_cd_get;
	state->ltm_hist_get = ori_state->ltm_hist_get;
#endif
#ifdef CONFIG_ENGIANT_VS_HISTOGRAM
	state->hist_get = ori_state->hist_get;
	state->rgb_hist_get = ori_state->rgb_hist_get;
#endif

	if (state->prior_gamma)
		drm_property_blob_get(state->prior_gamma);
	if (state->roi0_gamma)
		drm_property_blob_get(state->roi0_gamma);
	if (state->roi1_gamma)
		drm_property_blob_get(state->roi1_gamma);
#ifdef CONFIG_ENGIANT_VS_LTM
	if (state->ltm_luma_get)
		drm_property_blob_get(state->ltm_luma_get);
	if (state->ltm_cd_get)
		drm_property_blob_get(state->ltm_cd_get);
	if (state->ltm_hist_get)
		drm_property_blob_get(state->ltm_hist_get);
#endif
#ifdef CONFIG_ENGIANT_VS_HISTOGRAM
	if (state->hist_get)
		drm_property_blob_get(state->hist_get);
	if (state->rgb_hist_get)
		drm_property_blob_get(state->rgb_hist_get);
#endif

	// Skip dc property
}

static int _vs_crtc_set_property_blob_from_id(struct drm_device *dev,
						  struct drm_property_blob **blob, uint64_t blob_id,
						  size_t expected_size, bool *changed)
{
	struct drm_property_blob *new_blob = NULL;
	bool data_changed = false;

	if (blob_id) {
		new_blob = drm_property_lookup_blob(dev, blob_id);
		if (!new_blob)
			return -EINVAL;

		if (new_blob->length != expected_size) {
			drm_property_blob_put(new_blob);
			return -EINVAL;
		}
	}

	/* compare the ori blob data with the new blob data whether to changed. */
	if ((*blob) && blob_id) {
		if (memcmp(new_blob->data, (*blob)->data, expected_size) == 0) {
			drm_property_blob_put(new_blob);
			if (changed)
				*changed = false;
			return 0;
		}
	}

	data_changed = drm_property_replace_blob(blob, new_blob);
	if (changed)
		*changed = data_changed;

	drm_property_blob_put(new_blob);

	return 0;
}

static struct drm_crtc_state *vs_crtc_atomic_duplicate_state(struct drm_crtc *crtc)
{
	struct vs_crtc_state *ori_state;
	struct vs_crtc_state *state;
	const struct vs_crtc *vs_crtc = to_vs_crtc_const(crtc);

	if (WARN_ON(!crtc->state))
		return NULL;

	ori_state = to_vs_crtc_state(crtc->state);
	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return NULL;

	__drm_atomic_helper_crtc_duplicate_state(crtc, &state->base);

	state->sync_mode = ori_state->sync_mode;
	state->output_fmt = ori_state->output_fmt;
	state->encoder_type = ori_state->encoder_type;
	state->bpp = ori_state->bpp;
	state->sync_enable = ori_state->sync_enable;
	state->underflow = ori_state->underflow;
	state->out_dp = ori_state->out_dp;
	state->prior_gamma_changed = false;
	state->roi0_gamma_changed = false;
	state->roi1_gamma_changed = false;
#ifdef CONFIG_ENGIANT_VS_LTM
	state->ltm_luma_get_changed = false;
	state->ltm_cd_get_changed = false;
	state->ltm_hist_get_changed = false;
#endif
#ifdef CONFIG_ENGIANT_VS_HISTOGRAM
	state->hist_get_changed = false;
	state->rgb_hist_get_changed = false;
#endif

#ifdef CONFIG_ENGIANT_VS_MMU
	state->mmu_prefetch = ori_state->mmu_prefetch;
#endif

#ifdef CONFIG_DEBUG_FS
	state->qos = ori_state->qos;
#endif

	_vs_crtc_duplicate_blob(state, ori_state);

	/* dc properties */
	vs_egt_dc_duplicate_drm_properties(state->drm_states, ori_state->drm_states,
					   &vs_crtc->properties);

	return &state->base;
}

static void vs_crtc_atomic_destroy_state(struct drm_crtc *crtc, struct drm_crtc_state *state)
{
	struct vs_crtc_state *vs_crtc_state = to_vs_crtc_state(state);
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);

	__drm_atomic_helper_crtc_destroy_state(state);
#ifdef CONFIG_ENGIANT_VS_RCD
	if (vs_crtc_state->rcd_mask)
		drm_framebuffer_put(vs_crtc_state->rcd_mask);
#endif
#ifdef CONFIG_ENGIANT_VS_BLUR
	if (vs_crtc_state->blur_mask)
		drm_framebuffer_put(vs_crtc_state->blur_mask);
#endif
#ifdef CONFIG_ENGIANT_VS_BRIGHTNESS
	if (vs_crtc_state->brightness_mask)
		drm_framebuffer_put(vs_crtc_state->brightness_mask);
#endif
	drm_property_blob_put(vs_crtc_state->prior_gamma);
	drm_property_blob_put(vs_crtc_state->roi0_gamma);
	drm_property_blob_put(vs_crtc_state->roi1_gamma);
#ifdef CONFIG_ENGIANT_VS_LTM
	drm_property_blob_put(vs_crtc_state->ltm_luma_get);
	drm_property_blob_put(vs_crtc_state->ltm_cd_get);
	drm_property_blob_put(vs_crtc_state->ltm_hist_get);
#endif
#ifdef CONFIG_ENGIANT_VS_HISTOGRAM
	drm_property_blob_put(vs_crtc_state->hist_get);
	drm_property_blob_put(vs_crtc_state->rgb_hist_get);
#endif

	/* dc properties */
	vs_egt_dc_destroy_drm_properties(vs_crtc_state->drm_states, &vs_crtc->properties);
	kfree(vs_crtc_state);
}

static int vs_crtc_atomic_set_property(struct drm_crtc *crtc, struct drm_crtc_state *state,
					   struct drm_property *property, uint64_t val)
{
	struct drm_device *dev = crtc->dev;
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);
	struct vs_crtc_state *vs_crtc_state = to_vs_crtc_state(state);
	int ret = 0;
#ifdef CONFIG_ENGIANT_VS_RCD_BLUR_BRT
	struct drm_minor *minor = dev->primary;
	struct drm_file *file_priv = NULL;

	mutex_lock(&dev->filelist_mutex);
	list_for_each_entry(file_priv, &dev->filelist, lhead) {
		if (file_priv->minor == minor)
			break;
	}
	mutex_unlock(&dev->filelist_mutex);
#endif

	if (property == vs_crtc->sync_mode) {
		vs_crtc_state->sync_mode = val;
	} else if (property == vs_crtc->mmu_prefetch) {
		vs_crtc_state->mmu_prefetch = val;
	} else if (property == vs_crtc->panel_sync) {
		vs_crtc_state->sync_enable = val;
	} else if (property == vs_crtc->prior_gamma_prop) {
		ret = _vs_crtc_set_property_blob_from_id(dev, &vs_crtc_state->prior_gamma, val,
							 sizeof(struct drm_vs_egt_gamma_lut),
							 &vs_crtc_state->prior_gamma_changed);
	} else if (property == vs_crtc->roi0_gamma_prop) {
		ret = _vs_crtc_set_property_blob_from_id(dev, &vs_crtc_state->roi0_gamma, val,
							 sizeof(struct drm_vs_egt_gamma_lut),
							 &vs_crtc_state->roi0_gamma_changed);
	} else if (property == vs_crtc->roi1_gamma_prop) {
		ret = _vs_crtc_set_property_blob_from_id(dev, &vs_crtc_state->roi1_gamma, val,
							 sizeof(struct drm_vs_egt_gamma_lut),
							 &vs_crtc_state->roi1_gamma_changed);
	}
#ifdef CONFIG_ENGIANT_VS_LTM
	else if (property == vs_crtc->ltm_luma_get_prop) {
		ret = _vs_crtc_set_property_blob_from_id(dev, &vs_crtc_state->ltm_luma_get, val,
							 sizeof(struct drm_vs_egt_ltm_luma_ave),
							 &vs_crtc_state->ltm_luma_get_changed);
	} else if (property == vs_crtc->ltm_cd_get_prop) {
		ret = _vs_crtc_set_property_blob_from_id(dev, &vs_crtc_state->ltm_cd_get, val,
							 sizeof(struct drm_vs_egt_ltm_cd_get),
							 &vs_crtc_state->ltm_cd_get_changed);
	} else if (property == vs_crtc->ltm_hist_get_prop) {
		ret = _vs_crtc_set_property_blob_from_id(dev, &vs_crtc_state->ltm_hist_get, val,
							 sizeof(struct drm_vs_egt_ltm_hist_get),
							 &vs_crtc_state->ltm_hist_get_changed);
	}
#endif
#ifdef CONFIG_ENGIANT_VS_HISTOGRAM
	else if (property == vs_crtc->hist_get_prop) {
		ret = _vs_crtc_set_property_blob_from_id(dev, &vs_crtc_state->hist_get, val,
							 sizeof(struct drm_vs_egt_hist_get),
							 &vs_crtc_state->hist_get_changed);
	} else if (property == vs_crtc->rgb_hist_get_prop) {
		ret = _vs_crtc_set_property_blob_from_id(dev, &vs_crtc_state->rgb_hist_get, val,
							 sizeof(struct drm_vs_egt_rgb_hist_get),
							 &vs_crtc_state->rgb_hist_get_changed);
	}
#endif
#ifdef CONFIG_ENGIANT_VS_RCD
	else if (property == vs_crtc->rcd_mask_fb) {
		vs_crtc_state->rcd_mask =
			drm_framebuffer_lookup(crtc->dev, file_priv, (u32)(val & 0xFFFFFFFF));
	}
#endif
#ifdef CONFIG_ENGIANT_VS_BLUR
	else if (property == vs_crtc->blur_mask_fb) {
		vs_crtc_state->blur_mask =
			drm_framebuffer_lookup(crtc->dev, file_priv, (u32)(val & 0xFFFFFFFF));
	}
#endif
#ifdef CONFIG_ENGIANT_VS_BRIGHTNESS
	else if (property == vs_crtc->brightness_mask_fb) {
		vs_crtc_state->brightness_mask =
			drm_framebuffer_lookup(crtc->dev, file_priv, (u32)(val & 0xFFFFFFFF));
	}
#endif
	else {
		/* dc property */
		ret = vs_egt_dc_set_drm_property(dev, vs_crtc_state->drm_states,
				&vs_crtc->properties, property, val);
	}

	return ret;
}

static int vs_crtc_atomic_get_property(struct drm_crtc *crtc, const struct drm_crtc_state *state,
					   struct drm_property *property, uint64_t *val)
{
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);
	const struct vs_crtc_state *vs_crtc_state =
		container_of(state, const struct vs_crtc_state, base);

	if (property == vs_crtc->sync_mode)
		*val = vs_crtc_state->sync_mode;
	else if (property == vs_crtc->mmu_prefetch)
		*val = vs_crtc_state->mmu_prefetch;
	else if (property == vs_crtc->panel_sync)
		*val = vs_crtc_state->sync_enable;
	else if (property == vs_crtc->prior_gamma_prop)
		*val = (vs_crtc_state->prior_gamma) ? vs_crtc_state->prior_gamma->base.id : 0;
	else if (property == vs_crtc->roi0_gamma_prop)
		*val = (vs_crtc_state->roi0_gamma) ? vs_crtc_state->roi0_gamma->base.id : 0;
	else if (property == vs_crtc->roi1_gamma_prop)
		*val = (vs_crtc_state->roi1_gamma) ? vs_crtc_state->roi1_gamma->base.id : 0;
#ifdef CONFIG_ENGIANT_VS_LTM
	else if (property == vs_crtc->ltm_luma_get_prop)
		*val = (vs_crtc_state->ltm_luma_get) ? vs_crtc_state->ltm_luma_get->base.id : 0;
	else if (property == vs_crtc->ltm_cd_get_prop)
		*val = (vs_crtc_state->ltm_cd_get) ? vs_crtc_state->ltm_cd_get->base.id : 0;
	else if (property == vs_crtc->ltm_hist_get_prop)
		*val = (vs_crtc_state->ltm_hist_get) ? vs_crtc_state->ltm_hist_get->base.id : 0;
#endif
#ifdef CONFIG_ENGIANT_VS_HISTOGRAM
	else if (property == vs_crtc->hist_get_prop)
		*val = (vs_crtc_state->hist_get) ? vs_crtc_state->hist_get->base.id : 0;
	else if (property == vs_crtc->rgb_hist_get_prop)
		*val = (vs_crtc_state->rgb_hist_get) ? vs_crtc_state->rgb_hist_get->base.id : 0;
#endif
#ifdef CONFIG_ENGIANT_VS_RCD
	else if (property == vs_crtc->rcd_mask_fb)
		*val = (vs_crtc_state->rcd_mask) ? vs_crtc_state->rcd_mask->base.id : 0;
#endif
#ifdef CONFIG_ENGIANT_VS_BLUR
	else if (property == vs_crtc->blur_mask_fb)
		*val = (vs_crtc_state->blur_mask) ? vs_crtc_state->blur_mask->base.id : 0;
#endif
#ifdef CONFIG_ENGIANT_VS_BRIGHTNESS
	else if (property == vs_crtc->brightness_mask_fb)
		*val = (vs_crtc_state->brightness_mask) ?
			vs_crtc_state->brightness_mask->base.id : 0;
#endif
	else {
		/* dc property */
		return vs_egt_dc_get_drm_property(vs_crtc_state->drm_states, &vs_crtc->properties,
						  property, val);
	}
	return 0;
}

#ifdef CONFIG_DEBUG_FS
static int vs_crtc_debugfs_show(struct seq_file *s, __maybe_unused void *data)
{
	struct drm_crtc *crtc = s->private;
	struct vs_crtc_state *crtc_state = to_vs_crtc_state(crtc->state);
	struct drm_display_mode *mode = &crtc->state->adjusted_mode;

	seq_printf(s, "crtc[%u]: %s\n", crtc->base.id, crtc->name);
	seq_printf(s, "\tactive = %d\n", crtc->state->active);
	seq_printf(s, "\tsize = %dx%d\n", mode->hdisplay, mode->vdisplay);
	seq_printf(s, "\tbpp = %u\n", crtc_state->bpp);
	seq_printf(s, "\tunderflow = %d\n", crtc_state->underflow);

	return 0;
}

static int vs_crtc_debugfs_open(struct inode *inode, struct file *file)
{
	return single_open(file, vs_crtc_debugfs_show, inode->i_private);
}

static const struct file_operations vs_crtc_debugfs_fops = {
	.owner = THIS_MODULE,
	.open = vs_crtc_debugfs_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int vs_crtc_pattern_show(struct seq_file *s, __maybe_unused void *data)
{
	struct drm_crtc *crtc = s->private;
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);

	return vs_crtc->funcs->show_pattern_config(s);
}

static int vs_crtc_pattern_open(struct inode *inode, struct file *file)
{
	return single_open(file, vs_crtc_pattern_show, inode->i_private);
}

static ssize_t vs_crtc_pattern_write(struct file *file, const char __user *ubuf, size_t len,
					 __maybe_unused loff_t *offp)
{
	struct seq_file *s = file->private_data;
	struct drm_crtc *crtc = s->private;
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);

	if (vs_crtc->funcs->set_pattern)
		vs_crtc->funcs->set_pattern(crtc, ubuf, len);

	return len;
}

static int vs_crtc_crc_show(struct seq_file *s, __maybe_unused void *data)
{
	struct drm_crtc *crtc = s->private;
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);

	if (!vs_crtc->funcs->show_crc)
		return -EINVAL;

	return vs_crtc->funcs->show_crc(s);
}

static ssize_t vs_crtc_crc_write(struct file *file, const char __user *ubuf, size_t len,
				 __maybe_unused loff_t *offp)
{
	struct seq_file *s = file->private_data;
	struct drm_crtc *crtc = s->private;
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);

	if (vs_crtc->funcs->set_crc)
		vs_crtc->funcs->set_crc(vs_crtc->dev, crtc, ubuf, len);

	return len;
}

static int vs_crtc_crc_open(struct inode *inode, struct file *file)
{
	return single_open(file, vs_crtc_crc_show, inode->i_private);
}

static int vs_crtc_qos_show(struct seq_file *s, __maybe_unused void *data)
{
	struct drm_crtc *crtc = s->private;
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);

	if (vs_crtc->funcs->show_qos)
		return vs_crtc->funcs->show_qos(s);

	return 0;
}

static int vs_crtc_qos_open(struct inode *inode, struct file *file)
{
	return single_open(file, vs_crtc_qos_show, inode->i_private);
}

static ssize_t vs_crtc_qos_write(struct file *file, const char __user *ubuf, size_t len,
				 __maybe_unused loff_t *offp)
{
	struct seq_file *s = file->private_data;
	struct drm_crtc *crtc = s->private;
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);

	if (vs_crtc->funcs->set_qos)
		vs_crtc->funcs->set_qos(vs_crtc->dev, crtc, ubuf, len);

	return len;
}

static const struct file_operations vs_crtc_pattern_fops = {
	.owner = THIS_MODULE,
	.open = vs_crtc_pattern_open,
	.read = seq_read,
	.write = vs_crtc_pattern_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static const struct file_operations vs_crtc_crc_fops = {
	.owner = THIS_MODULE,
	.open = vs_crtc_crc_open,
	.read = seq_read,
	.write = vs_crtc_crc_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static const struct file_operations vs_crtc_qos_fops = {
	.owner = THIS_MODULE,
	.open = vs_crtc_qos_open,
	.read = seq_read,
	.write = vs_crtc_qos_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static int vs_crtc_debugfs_init(struct drm_crtc *crtc)
{
	debugfs_create_file("status", 0444, crtc->debugfs_entry, crtc, &vs_crtc_debugfs_fops);

	debugfs_create_file("pattern", 0644, crtc->debugfs_entry, crtc, &vs_crtc_pattern_fops);

	debugfs_create_file("CRC", 0644, crtc->debugfs_entry, crtc, &vs_crtc_crc_fops);

	debugfs_create_file("QOS", 0644, crtc->debugfs_entry, crtc, &vs_crtc_qos_fops);

	return 0;
}
#else
static int vs_crtc_debugfs_init(struct drm_crtc *crtc)
{
	return 0;
}
#endif /* CONFIG_DEBUG_FS */

static int vs_crtc_late_register(struct drm_crtc *crtc)
{
	return vs_crtc_debugfs_init(crtc);
}

static int vs_crtc_enable_vblank(struct drm_crtc *crtc)
{
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);

	vs_crtc->funcs->enable_vblank(vs_crtc, true);

	return 0;
}

static void vs_crtc_disable_vblank(struct drm_crtc *crtc)
{
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);

	vs_crtc->funcs->enable_vblank(vs_crtc, false);
}

static uint32_t vs_crtc_get_vblank_count(struct drm_crtc *crtc)
{
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);

	return vs_crtc->funcs->get_vblank_count(vs_crtc);
}

static const struct drm_crtc_funcs vs_crtc_funcs = {
	.set_config = drm_atomic_helper_set_config,
	.destroy = vs_egt_crtc_destroy,
	.page_flip = drm_atomic_helper_page_flip,
	.reset = vs_crtc_reset,
	.atomic_duplicate_state = vs_crtc_atomic_duplicate_state,
	.atomic_destroy_state = vs_crtc_atomic_destroy_state,
	.atomic_set_property = vs_crtc_atomic_set_property,
	.atomic_get_property = vs_crtc_atomic_get_property,
	.late_register = vs_crtc_late_register,
	.enable_vblank = vs_crtc_enable_vblank,
	.disable_vblank = vs_crtc_disable_vblank,
	.get_vblank_counter = vs_crtc_get_vblank_count,
	.get_vblank_timestamp = drm_crtc_vblank_helper_get_vblank_timestamp,
};

static u8 cal_pixel_bits(u32 bus_format)
{
	u8 bpp;

	switch (bus_format) {
	case MEDIA_BUS_FMT_RGB565_1X16:
	case MEDIA_BUS_FMT_UYVY8_1X16:
		bpp = 16;
		break;
	case MEDIA_BUS_FMT_RGB666_1X18:
	case MEDIA_BUS_FMT_RGB666_1X24_CPADHI:
		bpp = 18;
		break;
	case MEDIA_BUS_FMT_UYVY10_1X20:
		bpp = 20;
		break;
	case MEDIA_BUS_FMT_BGR888_1X24:
	case MEDIA_BUS_FMT_UYYVYY8_0_5X24:
	case MEDIA_BUS_FMT_YUV8_1X24:
		bpp = 24;
		break;
	case MEDIA_BUS_FMT_RGB101010_1X30:
	case MEDIA_BUS_FMT_UYYVYY10_0_5X30:
	case MEDIA_BUS_FMT_YUV10_1X30:
		bpp = 30;
		break;
	default:
		bpp = 24;
		break;
	}

	return bpp;
}

static bool vs_crtc_mode_fixup(struct drm_crtc *crtc, const struct drm_display_mode *mode,
				   struct drm_display_mode *adjusted_mode)
{
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);

	return vs_crtc->funcs->mode_fixup(vs_crtc->dev, mode, adjusted_mode);
}

static void vs_crtc_atomic_enable(struct drm_crtc *crtc,
				  __maybe_unused struct drm_atomic_state *old_state)
{
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);
	struct vs_crtc_state *vs_crtc_state = to_vs_crtc_state(crtc->state);
	struct drm_device *dev = crtc->dev;

	vs_crtc_state->bpp = cal_pixel_bits(vs_crtc_state->output_fmt);

	vs_crtc->funcs->enable(vs_crtc->dev, crtc);

	drm_crtc_vblank_on(crtc);
	drm_crtc_vblank_get(crtc);

	egt_dp_source_video_state(dev, DRM_MODE_DPMS_ON);
}

static void vs_crtc_atomic_disable(struct drm_crtc *crtc,
				   struct drm_atomic_state *old_state)
{
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);
	struct drm_crtc_state *crtc_old_state = NULL;
	struct drm_device *dev = crtc->dev;

	crtc_old_state = drm_atomic_get_old_crtc_state(old_state, crtc);

	if (crtc->state->mode_changed && !crtc->state->active_changed) {
		drm_crtc_vblank_put(crtc);
		drm_crtc_vblank_off(crtc);
		return;
	}

	vs_crtc->funcs->disable(vs_crtc->dev, crtc);

	drm_atomic_helper_disable_planes_on_crtc(crtc_old_state, true);

	if (!completion_done(&vs_crtc->frame_completion))
		wait_for_completion_timeout(&vs_crtc->frame_completion, 10 * 1000);

	vs_egt_crtc_handle_vblank(crtc);
	vs_egt_crtc_handle_flip_done(crtc);

	drm_crtc_vblank_put(crtc);
	drm_crtc_vblank_off(crtc);

	egt_dp_source_video_state(dev, DRM_MODE_DPMS_OFF);
}

static void vs_crtc_atomic_begin(struct drm_crtc *crtc,
				 __maybe_unused struct drm_atomic_state *old_crtc_state)
{
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);
	struct device *dev = vs_crtc->dev;

	if (vs_crtc->funcs->config)
		vs_crtc->funcs->config(dev, crtc);
}

static void vs_crtc_atomic_flush(struct drm_crtc *crtc,
				 __maybe_unused struct drm_atomic_state *old_crtc_state)
{
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);
	unsigned long flags;

	spin_lock_irqsave(&crtc->dev->event_lock, flags);
	vs_crtc->commit_hw_done = false;
	vs_crtc->event = crtc->state->event;
	crtc->state->event = NULL;
	spin_unlock_irqrestore(&crtc->dev->event_lock, flags);

	vs_crtc->funcs->commit(vs_crtc->dev, crtc);
}

static int vs_crtc_atomic_check(struct drm_crtc *crtc, struct drm_atomic_state *state)
{
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);
	struct drm_crtc_state *crtc_state = NULL;

	if (!crtc)
		return -EINVAL;

	crtc_state = drm_atomic_get_new_crtc_state(state, crtc);

	if (!crtc_state->enable || !crtc_state->active)
		return 0;

	return vs_crtc->funcs->check(vs_crtc->dev, crtc, crtc_state);
}

static bool vs_crtc_get_scanout_position(struct drm_crtc *crtc, bool in_vblank_irq, int *vpos,
					 int *hpos, ktime_t *stime, ktime_t *etime,
					 const struct drm_display_mode *mode)
{
	struct drm_device *dev = crtc->dev;
	unsigned int pipe = crtc->index;

	return vs_egt_display_get_crtc_scanoutpos(dev, pipe, in_vblank_irq,
			vpos, hpos, stime, etime, mode);
}

static const struct drm_crtc_helper_funcs vs_crtc_helper_funcs = {
	.mode_fixup = vs_crtc_mode_fixup,
	.atomic_enable = vs_crtc_atomic_enable,
	.atomic_disable = vs_crtc_atomic_disable,
	.atomic_begin = vs_crtc_atomic_begin,
	.atomic_flush = vs_crtc_atomic_flush,
	.atomic_check = vs_crtc_atomic_check,
	.get_scanout_position = vs_crtc_get_scanout_position,
};

static const struct drm_prop_enum_list vs_sync_mode_enum_list[] = {
	{ VS_EGT_SINGLE_DC, "single dc mode" },
	{ VS_EGT_MULTI_DC_PRIMARY, "primary dc for multi dc mode" },
	{ VS_EGT_MULTI_DC_SECONDARY, "secondary dc for multi dc mode" },
};

#ifdef CONFIG_ENGIANT_VS_MMU
static const struct drm_prop_enum_list vs_mmu_prefetch_enum_list[] = {
	{ VS_EGT_MMU_PREFETCH_DISABLE, "disable mmu prefetch" },
	{ VS_EGT_MMU_PREFETCH_ENABLE, "enable mmu prefetch" },
};
#endif

struct vs_crtc *vs_egt_crtc_create(const struct dc_hw_display *display, struct drm_device *drm_dev,
				   const struct vs_dc_info *info, u8 index)
{
	struct vs_crtc *crtc;
	struct vs_display_info *display_info = NULL;
	int ret;

	if (!info)
		return NULL;

	display_info = (struct vs_display_info *)&info->displays[index];
	if (!display_info)
		return NULL;

	crtc = kzalloc(sizeof(*crtc), GFP_KERNEL);
	if (!crtc)
		return NULL;

	spin_lock_init(&crtc->slock);

	ret = drm_crtc_init_with_planes(drm_dev, &crtc->base, NULL, NULL, &vs_crtc_funcs,
					display_info->name ? display_info->name : NULL);
	if (ret)
		goto err_free_crtc;

	drm_crtc_helper_add(&crtc->base, &vs_crtc_helper_funcs);

	/* Set up the crtc properties */
	if (info->pipe_sync) {
		crtc->sync_mode = drm_property_create_enum(drm_dev, 0, "SYNC_MODE",
							   vs_sync_mode_enum_list,
							   ARRAY_SIZE(vs_sync_mode_enum_list));

		if (!crtc->sync_mode)
			goto err_cleanup_crts;

		drm_object_attach_property(&crtc->base.base, crtc->sync_mode, VS_EGT_SINGLE_DC);
	}

	if (display_info->gamma) {
		if (info->std_color_lut) {
			ret = drm_mode_crtc_set_gamma_size(&crtc->base, info->max_gamma_size);
			if (ret)
				goto err_cleanup_crts;

			drm_crtc_enable_color_mgmt(&crtc->base, 0, display_info->ccm_linear,
						   info->max_gamma_size);
		} else {
			crtc->prior_gamma_prop =
				drm_property_create(drm_dev, DRM_MODE_PROP_BLOB, "PRIOR_GAMMA", 0);

			if (!crtc->prior_gamma_prop)
				goto err_cleanup_crts;

			drm_object_attach_property(&crtc->base.base, crtc->prior_gamma_prop, 0);
		}

		if (display_info->lut_roi) {
			crtc->roi0_gamma_prop =
				drm_property_create(drm_dev, DRM_MODE_PROP_BLOB, "ROI0_GAMMA", 0);

			if (!crtc->roi0_gamma_prop)
				goto err_cleanup_crts;

			drm_object_attach_property(&crtc->base.base, crtc->roi0_gamma_prop, 0);

			crtc->roi1_gamma_prop =
				drm_property_create(drm_dev, DRM_MODE_PROP_BLOB, "ROI1_GAMMA", 0);

			if (!crtc->roi1_gamma_prop)
				goto err_cleanup_crts;

			drm_object_attach_property(&crtc->base.base, crtc->roi1_gamma_prop, 0);
		}
	}

	if (info->panel_sync) {
		crtc->panel_sync = drm_property_create_bool(drm_dev, 0, "SYNC_ENABLED");

		if (!crtc->panel_sync)
			goto err_cleanup_crts;

		drm_object_attach_property(&crtc->base.base, crtc->panel_sync, 0);
	}
#ifdef CONFIG_ENGIANT_VS_LTM
	if (display_info->ltm && (display_info->id == 0)) {
		crtc->ltm_luma_get_prop =
			drm_property_create(drm_dev, DRM_MODE_PROP_BLOB, "LTM_LUMA_AVE_GET", 0);

		if (!crtc->ltm_luma_get_prop)
			goto err_cleanup_crts;

		drm_object_attach_property(&crtc->base.base, crtc->ltm_luma_get_prop, 0);

		crtc->ltm_cd_get_prop =
			drm_property_create(drm_dev, DRM_MODE_PROP_BLOB, "LTM_HIST_CD_GET", 0);

		if (!crtc->ltm_cd_get_prop)
			goto err_cleanup_crts;

		drm_object_attach_property(&crtc->base.base, crtc->ltm_cd_get_prop, 0);

		crtc->ltm_hist_get_prop =
			drm_property_create(drm_dev, DRM_MODE_PROP_BLOB, "LTM_LOCAL_HIST_GET", 0);

		if (!crtc->ltm_hist_get_prop)
			goto err_cleanup_crts;

		drm_object_attach_property(&crtc->base.base, crtc->ltm_hist_get_prop, 0);
	}
#endif

#ifdef CONFIG_ENGIANT_VS_HISTOGRAM
	if (display_info->histogram && (display_info->id == 0 || display_info->id == 1)) {
		crtc->hist_get_prop =
			drm_property_create(drm_dev, DRM_MODE_PROP_BLOB, "HIST_GET", 0);

		if (!crtc->hist_get_prop)
			goto err_cleanup_crts;

		drm_object_attach_property(&crtc->base.base, crtc->hist_get_prop, 0);
	}

	if (display_info->rgb_hist && (display_info->id == 0)) {
		crtc->rgb_hist_get_prop =
			drm_property_create(drm_dev, DRM_MODE_PROP_BLOB, "RGB_HIST_GET", 0);

		if (!crtc->rgb_hist_get_prop)
			goto err_cleanup_crts;

		drm_object_attach_property(&crtc->base.base, crtc->rgb_hist_get_prop, 0);
	}
#endif

#ifdef CONFIG_ENGIANT_VS_RCD
	if (display_info->rcd) {
		crtc->rcd_mask_fb = drm_property_create_object(drm_dev, DRM_MODE_PROP_ATOMIC,
								   "RCD_MASK", DRM_MODE_OBJECT_FB);
		if (!crtc->rcd_mask_fb)
			goto err_cleanup_crts;

		drm_object_attach_property(&crtc->base.base, crtc->rcd_mask_fb, 0);
	}
#endif

#ifdef CONFIG_ENGIANT_VS_BLUR
	if (display_info->blur) {
		crtc->blur_mask_fb = drm_property_create_object(drm_dev, DRM_MODE_PROP_ATOMIC,
								"BLUR_MASK", DRM_MODE_OBJECT_FB);
		if (!crtc->blur_mask_fb)
			goto err_cleanup_crts;

		drm_object_attach_property(&crtc->base.base, crtc->blur_mask_fb, 0);
	}
#endif

#ifdef CONFIG_ENGIANT_VS_BRIGHTNESS
	if (display_info->brightness) {
		crtc->brightness_mask_fb = drm_property_create_object(
			drm_dev, DRM_MODE_PROP_ATOMIC, "BRIGHTNESS_MASK", DRM_MODE_OBJECT_FB);
		if (!crtc->brightness_mask_fb)
			goto err_cleanup_crts;

		drm_object_attach_property(&crtc->base.base, crtc->brightness_mask_fb, 0);
	}
#endif

	if (display != NULL && vs_egt_dc_create_drm_properties(drm_dev, &crtc->base.base,
							&display->states, &crtc->properties)) {
		goto err_cleanup_crts;
	}

#ifdef CONFIG_ENGIANT_VS_MMU
	if (info->mmu_prefetch) {
		crtc->mmu_prefetch = drm_property_create_enum(
			drm_dev, 0, "MMU_PREFETCH", vs_mmu_prefetch_enum_list,
			ARRAY_SIZE(vs_mmu_prefetch_enum_list));
		if (!crtc->mmu_prefetch)
			goto err_cleanup_crts;

		drm_object_attach_property(&crtc->base.base, crtc->mmu_prefetch,
					VS_EGT_MMU_PREFETCH_DISABLE);
	}
#endif

	crtc->max_bpc = info->max_bpc;
	crtc->color_formats = display_info->color_formats;
	crtc->id = index;
	return crtc;

err_cleanup_crts:
	drm_crtc_cleanup(&crtc->base);

err_free_crtc:
	kfree(crtc);
	return NULL;
}

void vs_egt_crtc_handle_vblank(struct drm_crtc *crtc)
{
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);

	vs_crtc->t_cut_vblank = ktime_get() - vs_crtc->t_vblank;
	vs_crtc->t_vblank = ktime_get();

	drm_crtc_handle_vblank(crtc);
}

void vs_egt_crtc_handle_frame_done(struct drm_crtc *crtc)
{
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);

	complete(&vs_crtc->frame_completion);
}

void vs_egt_crtc_handle_flip_done_while_hw_done(struct drm_crtc *crtc)
{
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);
	unsigned long flags;

	/* Init the frame completion */
	init_completion(&vs_crtc->frame_completion);

	if ((!vs_crtc->commit_hw_done) || (!vs_crtc->event))
		return;

	spin_lock_irqsave(&crtc->dev->event_lock, flags);
	drm_crtc_send_vblank_event(crtc, vs_crtc->event);
	vs_crtc->event = NULL;
	spin_unlock_irqrestore(&crtc->dev->event_lock, flags);
}

void vs_egt_crtc_handle_flip_done(struct drm_crtc *crtc)
{
	struct vs_crtc *vs_crtc = to_vs_crtc(crtc);
	unsigned long flags;

	/* Init the frame completion */
	init_completion(&vs_crtc->frame_completion);

	if (!vs_crtc->event)
		return;

	spin_lock_irqsave(&crtc->dev->event_lock, flags);
	drm_crtc_send_vblank_event(crtc, vs_crtc->event);
	vs_crtc->event = NULL;
	spin_unlock_irqrestore(&crtc->dev->event_lock, flags);
}
