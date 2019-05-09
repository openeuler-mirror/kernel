// SPDX-License-Identifier: GPL-2.0+
#include "config.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include <sys/poll.h>
#include "wd.h"
#include "wd_adapter.h"
#include "wd_util.h"

#define SYS_CLASS_DIR	"/sys/class"
#define WD_LATENCY	"latency"
#define WD_THROUGHPUT	"throughput"
#define _PAGE_SIZE	page_size
#define _PAGE_MASK	(~(_PAGE_SIZE - 1))

struct wd_algo_info;

struct wd_vfio_container {
	int container;
	int ref;
};

struct wd_dev_info {
	int node_id;
	int numa_distance;
	int iommu_type;
	int dma_flag;
	int group_fd;
	int mdev_fd;
	int ref;
	int is_load;
	char attr_path[PATH_STR_SIZE];
	char dev_root[PATH_STR_SIZE];
	char name[WD_NAME_SZ];
	char mdev_name[SYS_VAL_SIZE];
	char group_id[SYS_VAL_SIZE];
	char *udrv;
	struct wd_algo_info *alg_list;

	TAILQ_ENTRY(wd_dev_info) next;
};

struct wd_algo_info {
	__u32 type;
	__u32 available_instances;
	struct wd_capa capa;
	char name[WD_NAME_SZ];
	char api[WD_NAME_SZ];
	char algo_path[PATH_STR_SIZE];
	struct wd_dev_info *dinfo;
	struct wd_algo_info *next;
};

TAILQ_HEAD(wd_dev_list, wd_dev_info);

static struct wd_dev_list wd_dev_cache_list =
	TAILQ_HEAD_INITIALIZER(wd_dev_cache_list);

static struct wd_lock _wd_pmutex = {0};

/* Global VFIO container */
static struct wd_vfio_container container = {0, 0};

static unsigned long page_size;

#if (defined(HAVE_SVA) & HAVE_SVA)

/* Currently, PASID is exposed to user space.
 * Try to avoid expose it in the next.
 */
static int _wd_bind_process(struct wd_queue *q)
{
	struct bind_data {
		struct vfio_iommu_type1_bind bind;
		struct vfio_iommu_type1_bind_process data;
	} wd_bind;
	int ret;
	__u32 flags = 0;

	if (q->dma_flag & VFIO_SPIMDEV_DMA_MULTI_PROC_MAP)
		flags = VFIO_IOMMU_BIND_PRIV;
	else if (q->dma_flag & VFIO_SPIMDEV_DMA_SVM_NO_FAULT)
		flags = VFIO_IOMMU_BIND_NOPF;

	wd_bind.bind.flags = VFIO_IOMMU_BIND_PROCESS;
	wd_bind.bind.argsz = sizeof(wd_bind);
	wd_bind.data.flags = flags;
	ret = ioctl(q->container, VFIO_IOMMU_BIND, &wd_bind);
	if (ret)
		return ret;
	q->pasid = wd_bind.data.pasid;
	return ret;
}

static int _wd_unbind_process(struct wd_queue *q)
{
	struct bind_data {
		struct vfio_iommu_type1_bind bind;
		struct vfio_iommu_type1_bind_process data;
	} wd_bind;
	__u32 flags = 0;

	if (q->dma_flag & VFIO_SPIMDEV_DMA_MULTI_PROC_MAP)
		flags = VFIO_IOMMU_BIND_PRIV;
	else if (q->dma_flag & VFIO_SPIMDEV_DMA_SVM_NO_FAULT)
		flags = VFIO_IOMMU_BIND_NOPF;

	wd_bind.bind.flags = VFIO_IOMMU_BIND_PROCESS;
	wd_bind.data.pasid = q->pasid;
	wd_bind.data.flags = flags;
	wd_bind.bind.argsz = sizeof(wd_bind);

	return ioctl(q->container, VFIO_IOMMU_UNBIND, &wd_bind);
}
#endif

static int __alg_param_check(struct wd_algo_info *wa_info, struct wd_capa *capa)
{
	/* We think it is always matching now */
	return 0;
}

#if (defined(HAVE_DYNDRV) & HAVE_DYNDRV)
static int _drv_load_check(char *drv)
{
	struct wd_dev_info *wd_info;

	TAILQ_FOREACH(wd_info, &wd_dev_cache_list, next) {
		if (!strncmp(wd_info->udrv, drv, strlen(wd_info->udrv)))
			return 1;
	}

	return 0;
}
#endif

static int __capa_check(struct wd_algo_info *ainfo, struct wd_capa *capa)
{
	struct wd_capa *alg_capa = &ainfo->capa;

	if (strncmp(ainfo->name, capa->alg, strlen(capa->alg)))
		return -ENODEV;

	/* Not initiate */
	if (!alg_capa->latency || !alg_capa->throughput)
		return -ENODEV;

	/* Latency check */
	if (alg_capa->latency > 0 && alg_capa->latency > capa->latency)
		return -ENODEV;

	/* Throughput check */
	if (alg_capa->throughput > 0 && alg_capa->throughput < capa->throughput)
		return -ENODEV;

	/* Algorithm paremeters check */
	return __alg_param_check(ainfo, capa);
}

static void __add_alg(struct wd_algo_info *alg, struct wd_dev_info *wd_info)
{
	struct wd_algo_info *alg_list = wd_info->alg_list;

	wd_info->alg_list = alg;
	alg->next = alg_list;
}

static int _mdev_get(struct wd_dev_info *wd_info)
{
	char mdev_info[SYS_VAL_SIZE];
	int val;

	if (strlen(wd_info->group_id) > 0)
		return 0;
	memset(mdev_info, '\0', SYS_VAL_SIZE);
	val = _get_dir_attr_str(wd_info->attr_path, SPIMDEV_MDEV_GET,
			mdev_info);
	if (val <= 0)
		return val;
	mdev_info[val - 1] = '\0';
	memcpy(wd_info->mdev_name, mdev_info, UUID_STR_SZ);
	wd_info->mdev_name[UUID_STR_SZ] = '\0';
	strncpy(wd_info->group_id, &mdev_info[UUID_STR_SZ + 1],
		SYS_VAL_SIZE);

	return 0;
}

static int _get_wd_alg_info(struct wd_dev_info *dinfo, struct wd_capa *capa)
{
	char algo_path[PATH_STR_SIZE];
	DIR *drv_alg;
	struct dirent *attr_file;
	struct wd_algo_info *ainfo = NULL;
	char *sect, *d_alg;
	int cnt = 0, ret;

	strncpy(algo_path, dinfo->dev_root, PATH_STR_SIZE);
	strcat(algo_path, "/device/mdev_supported_types");
	drv_alg = opendir(algo_path);
	if (!drv_alg) {
		WD_ERR("opendir %s fail!\n", algo_path);
		return -ENODEV;
	}
	while ((attr_file = readdir(drv_alg)) != NULL) {
		if (strncmp(attr_file->d_name, ".", 1) == 0)
			continue;
		if (capa && !strstr(attr_file->d_name, capa->alg))
			continue;
		d_alg = attr_file->d_name;
		if (!ainfo) {
			ainfo = malloc(sizeof(*ainfo));
			if (!ainfo) {
				WD_ERR("alloc wa fail!\n");
				closedir(drv_alg);
				return -ENOMEM;
			}
		}
		memset(ainfo, 0, sizeof(*ainfo));
		strncpy(ainfo->algo_path, algo_path, PATH_STR_SIZE);
		strcat(ainfo->algo_path, "/");
		strcat(ainfo->algo_path, d_alg);
		sect = strstr(d_alg, "-");
		memcpy(ainfo->api, d_alg, sect - d_alg);
		strcpy(ainfo->name, sect + 1);
		ainfo->dinfo = dinfo;
#if (defined(HAVE_DYNDRV) & HAVE_DYNDRV)
		if (!dinfo->is_load && !_drv_load_check(ainfo->api)) {
			ret = _wd_dyn_load(ainfo->api);
			if (ret) {
				WD_ERR("WD load %s fail!\n", ainfo->api);
				goto no_alg_exit;
			}
			dinfo->is_load = 1;
		}
#endif
		ainfo->capa.alg = capa ? capa->alg : NULL;
		ret = _wd_get_capa(ainfo->api, &ainfo->capa);
		if (ret) {
			WD_ERR("WD get capa of %s fail!\n", ainfo->api);
			goto no_alg_exit;
		}
		if (capa && __capa_check(ainfo, capa) < 0)
			goto no_alg_exit;
		ainfo->available_instances =
		_get_dir_attr_int(ainfo->algo_path, "available_instances");
		if (ainfo->available_instances < 0)
			goto no_alg_exit;
		ainfo->type =
		_get_dir_attr_int(ainfo->algo_path, "type");
		__add_alg(ainfo, dinfo);
		dinfo->udrv = ainfo->api;
		if (capa) {
			closedir(drv_alg);
			return _mdev_get(dinfo);
		}
		cnt++;
		ainfo = NULL;
	}

no_alg_exit:
	if (capa) {
		free_obj(ainfo);
		closedir(drv_alg);
		return -ENODEV;
	}

	closedir(drv_alg);
	return cnt;
}

static int _get_dev_node_id(struct wd_dev_info *wd_info)
{
	int val;

	val = _get_dir_attr_int(wd_info->attr_path, SPIMDEV_NODE_ID);
	if (val >= 0)
		wd_info->node_id = val;
#if (defined(HAVE_NUMA) & HAVE_NUMA)
	if (val < 0) {
		WD_ERR("Please config NUMA in kernel!");
		return -EINVAL;
	}
#endif
	return 0;
}

#if (defined(HAVE_NUMA) & HAVE_NUMA)
static int _get_dev_numa_distance(struct wd_dev_info *wd_info)
{
	return  _get_dir_attr_int(wd_info->attr_path,
				  SPIMDEV_NUMA_DISTANCE);
}
#endif

static int _get_dev_iommu_type(struct wd_dev_info *wd_info)
{
	int val;

	val = _get_dir_attr_int(wd_info->attr_path, SPIMDEV_IOMMU_TYPE);
	if (val >= 0)
		wd_info->iommu_type = val;
	else
		return val;

	return 0;
}

static int _get_dev_dma_flag(struct wd_dev_info *wd_info)
{
	int val;

	val = _get_dir_attr_int(wd_info->attr_path, SPIMDEV_DMA_FLAG);
	if (val >= 0)
		wd_info->dma_flag = val;
	else
		return val;

	return 0;
}

static int _get_wd_dev_info(struct wd_dev_info *dinfo)
{
	char *attr_path = dinfo->attr_path;
	int ret;

	ret = snprintf(attr_path, PATH_STR_SIZE, "%s/%s", dinfo->dev_root,
		       "device/"VFIO_SPIMDEV_PDEV_ATTRS_GRP);
	if (ret < 0)
		return ret;
	ret = _get_dev_dma_flag(dinfo);
	if (ret)
		return ret;
	ret = _get_dev_iommu_type(dinfo);
	if (ret)
		return ret;
	ret = _get_dev_node_id(dinfo);
	if (ret)
		return ret;
#if (defined(HAVE_NUMA) & HAVE_NUMA)
	ret = _get_dev_numa_distance(dinfo);
	if (ret < 0)
		return ret;
	dinfo->numa_distance = ret;
#endif
	return 0;
}

static inline struct wd_dev_info *_get_cache_dev(char *name)
{
	struct wd_dev_info *dinfo;

	TAILQ_FOREACH(dinfo, &wd_dev_cache_list, next) {
		if (strncmp(dinfo->name, name, strlen(name)))
			continue;
		return dinfo;
	}

	return NULL;
}

static int _find_available_res(struct wd_capa *capa)
{
	DIR *wd_cls;
	struct dirent *device;
	struct wd_dev_info *dinfo, *wdev, *exist_mdev;
	int cnt = 0;
	struct wd_algo_info *alg;

	TAILQ_FOREACH(dinfo, &wd_dev_cache_list, next) {
		alg = dinfo->alg_list;
		while (alg && capa) {
			if (__capa_check(alg, capa)) {
				alg = alg->next;
				continue;
			}

			return 1;
		}
	}
	dinfo = NULL;
	wd_cls = opendir(SYS_CLASS_DIR"/"VFIO_SPIMDEV_CLASS_NAME);
	if (!wd_cls) {
		WD_ERR("WD framework is not enabled on this system!\n");
		return -ENODEV;
	}
	while ((device = readdir(wd_cls)) != NULL) {
		if (strncmp(device->d_name, ".", 1) == 0 ||
		    strncmp(device->d_name, "..", 2) == 0)
			continue;
		exist_mdev = _get_cache_dev(device->d_name);
		if (exist_mdev) {
			if (_get_wd_alg_info(exist_mdev, capa) < 0) {
				continue;
			} else {
				cnt++;
				break;
			}
		}
		dinfo = malloc(sizeof(*dinfo));
		if (!dinfo) {
			WD_ERR("alloc wdev fail!\n");
			closedir(wd_cls);
			return -ENOMEM;
		}
		memset(dinfo, 0, sizeof(*dinfo));
		(void)strncpy(dinfo->dev_root,
		SYS_CLASS_DIR"/"VFIO_SPIMDEV_CLASS_NAME"/", PATH_STR_SIZE);
		(void)strcat(dinfo->dev_root, device->d_name);

		/* To be updated. Algorithm name should be checked at first */
		if (_get_wd_dev_info(dinfo) < 0)
			continue;

		strncpy(dinfo->name, device->d_name, WD_NAME_SZ);
		if (_get_wd_alg_info(dinfo, capa) < 0)
			continue;
		cnt++;
		if (TAILQ_EMPTY(&wd_dev_cache_list)) {
			TAILQ_INSERT_TAIL(&wd_dev_cache_list, dinfo, next);
			dinfo = NULL;
		} else {
			TAILQ_FOREACH(wdev, &wd_dev_cache_list, next) {
				if (dinfo->numa_distance >
				    wdev->numa_distance &&
				    TAILQ_NEXT(wdev, next)) {
					continue;
				} else if (dinfo->numa_distance <=
					   wdev->numa_distance) {
					TAILQ_INSERT_BEFORE(wdev, dinfo, next);
					dinfo = NULL;
					break;
				}
				TAILQ_INSERT_AFTER(&wd_dev_cache_list,
						   wdev, dinfo, next);
				dinfo = NULL;
				break;
			}
		}
	}
	closedir(wd_cls);
	if (dinfo)
		free(dinfo);
	return cnt;
}

int wd_dump_all_algos(void)
{
	int ret;
	struct wd_dev_info *wd_info;
	struct wd_algo_info *alg;
	int dev_num = 0;

	wd_spinlock(&_wd_pmutex);
	ret = _find_available_res(NULL);
	if (ret <= 0) {
		wd_unspinlock(&_wd_pmutex);
		WD_ERR("No device!\n");
		return ret;
	}
	TAILQ_FOREACH(wd_info, &wd_dev_cache_list, next) {
		alg = wd_info->alg_list;
		printf("Device(%s): node_id=%d, priority=%d, iommu_type=%d\n",
			wd_info->name, wd_info->node_id,
			wd_info->numa_distance, wd_info->iommu_type);
		while (alg) {
			printf("  Alg(%s): flags=%d, available_instances=%d\n",
			alg->name, alg->type, alg->available_instances);
			alg = alg->next;
		}
		dev_num++;
	}
	wd_unspinlock(&_wd_pmutex);

	return dev_num;
}

int _get_mdev_group(struct wd_queue *q, struct wd_dev_info *dinfo)
{
	sprintf(q->vfio_group_path, "/dev/vfio/%s", dinfo->group_id);

	/* open group */
	q->group = open(q->vfio_group_path, O_RDWR);
	if (q->group < 0) {
		if (errno == EBUSY)
			return -EBUSY;
		WD_ERR("open vfio group fail(%s), ret=%d\n",
			q->vfio_group_path, q->group);
		return q->group;
	}
	dinfo->group_fd = q->group;

	return 0;
}

static void _put_algo_mdev(struct wd_queue *q)
{
	struct wd_algo_info *ainfo = q->alg_info;
	struct wd_dev_info *dinfo = ainfo->dinfo;

	(void)__atomic_sub_fetch(&dinfo->ref, 1, __ATOMIC_ACQUIRE);
}

static int _get_algo_mdev(struct wd_queue *q)
{
	int ret;
	struct wd_algo_info *ainfo;
	struct wd_dev_info *dinfo;

	/* Create by the order of priority of device */
	TAILQ_FOREACH(dinfo, &wd_dev_cache_list, next) {
		ainfo = dinfo->alg_list;
check_next_alg:
		if (!ainfo)
			continue;

		if (__capa_check(ainfo, &q->capa)) {
			ainfo = ainfo->next;
			goto check_next_alg;
		}
#if (defined(HAVE_NUMA) & HAVE_NUMA)
		ret = _get_dev_numa_distance(dinfo);
		if (ret < 0)
			return ret;
		if (ret > q->numa_dis) {
			if (!TAILQ_NEXT(dinfo, next)) {
				q->numa_dis++;
				return _get_algo_mdev(q);
			}
			continue;
		}
#endif
		q->iommu_type = ainfo->dinfo->iommu_type;
		if (dinfo->group_fd > 0) {
			q->mdev = dinfo->mdev_fd;
			q->group = dinfo->group_fd;
			q->is_new_group = 0;
			q->fd = ioctl(q->mdev,
				      VFIO_SPIMDEV_CMD_GET_Q,
				      (unsigned long)q->type);
			if (q->fd < 0)
				continue;
		} else {
			ret = _get_mdev_group(q, dinfo);
			if (ret) {
				WD_ERR("fail to open group: /dev/vfio/%s!\n",
				       dinfo->group_id);
				return ret;
			}
			q->is_new_group = 1;
		}
		strncpy(q->mdev_name, dinfo->mdev_name, WD_NAME_SZ);
		strncpy(q->hw_type, ainfo->api, WD_NAME_SZ);
		q->alg_info = ainfo;
		q->node_id = dinfo->node_id;
		q->type = ainfo->type;
		(void)__atomic_add_fetch(&dinfo->ref, 1, __ATOMIC_ACQUIRE);

		return 0;
	}
	return -ENODEV;
}

static int _get_vfio_facility(struct wd_queue *q)
{
	struct vfio_group_status group_status = {
		.argsz = sizeof(group_status) };
	struct wd_dev_info *dinfo;
	int ret = 0;
	int iommu_ext;

	dinfo = ((struct wd_algo_info *)q->alg_info)->dinfo;

	/* container from outside */
	if (q->container > 0) {
		container.container = q->container;
		q->is_ext_container = 1;
		page_size = (unsigned long)getpagesize();
	}

	if (q->container <= 0) {
		/* I think we need get an existing container */
		q->container = container.container;
		q->is_ext_container = 1;
	}

	if (q->container <= 0 && q->is_new_group) {

		/* Create a new vfio container */
		q->container = open("/dev/vfio/vfio", O_RDWR);
		if (q->container < 0) {
			WD_ERR("Create VFIO container fail!\n");
			return -ENODEV;
		}
		q->is_ext_container = 0;
		container.container = q->container;
		page_size = (unsigned long)getpagesize();

	/* while using old group, cannot create new container, because
	 * the old group has already been added into another container.
	 */
	} else if (q->container <= 0 && !q->is_new_group) {
		WD_ERR("%s():group %d already added into a container!\n",
			__func__, q->group);
		ret = -EINVAL;
		return ret;
	}

	/* Check the exist vfio container */
	if (ioctl(q->container, VFIO_GET_API_VERSION) != VFIO_API_VERSION) {
		WD_ERR("VFIO version check fail!\n");
		ret = -EINVAL;
		return ret;
	}

	/* Support the IOMMU driver we want. */
	iommu_ext = dinfo->iommu_type;
	if (ioctl(q->container, VFIO_CHECK_EXTENSION, iommu_ext) < 0) {
		WD_ERR("VFIO iommu check fail!\n");
		ret = -EINVAL;
		return ret;
	}

	if (!q->is_new_group)
		goto next_operation;

	ioctl(q->group, VFIO_GROUP_GET_STATUS, &group_status);
	if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
		WD_ERR("VFIO group is not viable\n");
		ret = -ENODEV;
		return ret;
	}

	if ((ioctl(q->group, VFIO_GROUP_SET_CONTAINER, &q->container))) {
		WD_ERR("VFIO group fail on VFIO_GROUP_SET_CONTAINER\n");
		ret = -ENODEV;
		return ret;
	}

	if (!q->is_ext_container &&
	    ioctl(q->container, VFIO_SET_IOMMU, iommu_ext)) {
		WD_ERR("VFIO fail on VFIO_SET_IOMMU(%d)\n", iommu_ext);
		ret = -ENODEV;
		return ret;
	}

	q->mdev = ioctl(q->group, VFIO_GROUP_GET_DEVICE_FD, q->mdev_name);
	if (q->mdev < 0) {
		WD_ERR("VFIO GET DEVICE %s FD fail!\n", q->mdev_name);
		ret = q->mdev;
		return ret;
	}
	dinfo->mdev_fd = q->mdev;

next_operation:
	(void)__atomic_add_fetch(&container.ref, 1, __ATOMIC_ACQUIRE);
	q->dma_flag = dinfo->dma_flag;
#if (defined(HAVE_SVA) & HAVE_SVA)
	if (!(q->dma_flag & (VFIO_SPIMDEV_DMA_PHY |
	    VFIO_SPIMDEV_DMA_SINGLE_PROC_MAP))) {
		ret = _wd_bind_process(q);
		if (ret) {
			close(q->mdev);
			WD_ERR("VFIO fails to bind process!\n");
			return ret;

		}
	}
#endif

	return 0;
}

static void _put_vfio_facility(struct wd_queue *q)
{
	struct wd_algo_info *ainfo = q->alg_info;
	struct wd_dev_info *dinfo = ainfo->dinfo;

#if (defined(HAVE_SVA) & HAVE_SVA)
	if (!(q->dma_flag & (VFIO_SPIMDEV_DMA_PHY |
	    VFIO_SPIMDEV_DMA_SINGLE_PROC_MAP))) {
		if (q->pasid <= 0) {
			WD_ERR("Wd queue pasid ! pasid=%d\n", q->pasid);
			return;
		}
		if (_wd_unbind_process(q)) {
			WD_ERR("VFIO fails to unbind process!\n");
			return;
		}
	}
#endif
	if (!__atomic_load_n(&dinfo->ref, __ATOMIC_ACQUIRE)) {
		if (q->mdev > 0) {
			dinfo->mdev_fd = 0;
			close(q->mdev);
		}
		if (q->group > 0) {
			dinfo->group_fd = 0;
			close(q->group);
		}
	}
	if (q->container > 0 &&
	     !__atomic_sub_fetch(&container.ref, 1, __ATOMIC_ACQUIRE)) {
		close(q->container);
		container.container = 0;
	}
}

int _get_queue(struct wd_queue *q)
{
	if (q->fd > 0)
		return 0;
	q->fd = ioctl(q->mdev,
		      VFIO_SPIMDEV_CMD_GET_Q,
		      (unsigned long)q->type);
	if (q->fd < 0)
		return -ENODEV;

	return 0;
}

static void _put_queue(struct wd_queue *q)
{
	close(q->fd);
}

int wd_request_queue(struct wd_queue *q)
{
	int ret = 0;

	wd_spinlock(&_wd_pmutex);
	ret = _find_available_res(&q->capa);
	if (ret <= 0) {
		wd_unspinlock(&_wd_pmutex);
		WD_ERR("Fail to find available algorithms!\n");
		return -ENODEV;
	}
	ret = _get_algo_mdev(q);
	if (ret) {
		wd_unspinlock(&_wd_pmutex);
		WD_ERR("Fail to get mdev!\n");
		return -ENODEV;
	}
	ret = _get_vfio_facility(q);
	if (ret) {
		WD_ERR("Fail to get VFIO facility!\n");
		goto out_with_mdev;
	}
	ret = _get_queue(q);
	if (ret) {
		WD_ERR("Fail to get queue!\n");
		goto out_with_mdev;
	}
	wd_unspinlock(&_wd_pmutex);
	ret = drv_open(q);
	if (ret) {
		WD_ERR("Driver queue init fail!\n");
		wd_spinlock(&_wd_pmutex);
		goto out_with_queue;
	}
	return ret;

out_with_queue:
	_put_queue(q);
out_with_mdev:
	_put_algo_mdev(q);
	_put_vfio_facility(q);
	wd_unspinlock(&_wd_pmutex);

	return ret;
}

void wd_release_queue(struct wd_queue *q)
{
	drv_close(q);
	wd_spinlock(&_wd_pmutex);
	_put_queue(q);
	_put_algo_mdev(q);
	_put_vfio_facility(q);
	wd_unspinlock(&_wd_pmutex);
}

int wd_send(struct wd_queue *q, void *req)
{
	return drv_send(q, req);
}

int wd_recv(struct wd_queue *q, void **resp)
{
	return drv_recv(q, resp);
}

static int wd_flush_and_wait(struct wd_queue *q, __u16 ms)
{
	struct pollfd fds[1];

	wd_flush(q);
	fds[0].fd = q->fd;
	fds[0].events = POLLIN;
	return poll(fds, 1, ms);
}

int wd_recv_sync(struct wd_queue *q, void **resp, __u16 ms)
{
	int ret;

	while (1) {
		ret = wd_recv(q, resp);
		if (ret == -EBUSY) {
			ret = wd_flush_and_wait(q, ms);
			if (ret)
				return ret;
		} else
			return ret;
	}
}

void wd_flush(struct wd_queue *q)
{
	drv_flush(q);
}

static int _wd_mem_share_type1(struct wd_queue *q, const void *addr,
			       size_t size, int flags)
{
	struct vfio_iommu_type1_dma_map dma_map;

	if (q->dma_flag & VFIO_SPIMDEV_DMA_PHY)
		return 0;
	if (q->dma_flag & VFIO_SPIMDEV_DMA_SVM_NO_FAULT)
		return mlock(addr, size);

#if (defined(HAVE_SVA) & HAVE_SVA)
	else if ((q->dma_flag & VFIO_SPIMDEV_DMA_MULTI_PROC_MAP) &&
		 (q->pasid > 0))
		dma_map.pasid = q->pasid;
#endif
	else if ((q->dma_flag & VFIO_SPIMDEV_DMA_SINGLE_PROC_MAP))
		;
	else
		return -1;

	size = ((size - 1) & _PAGE_MASK) + _PAGE_SIZE;
	dma_map.vaddr = (__u64)addr & _PAGE_MASK;
	dma_map.size = size;
	dma_map.iova = dma_map.vaddr;
	dma_map.flags =
		VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE | flags;
	dma_map.argsz = sizeof(dma_map);

	return ioctl(q->container, VFIO_IOMMU_MAP_DMA, &dma_map);
}

static void _wd_mem_unshare_type1(struct wd_queue *q, const void *addr,
				  size_t size)
{
	struct vfio_iommu_type1_dma_unmap dma_unmap;

	if (q->dma_flag & VFIO_SPIMDEV_DMA_PHY)
		return;
	if (q->dma_flag & VFIO_SPIMDEV_DMA_SVM_NO_FAULT) {
		(void)munlock(addr, size);
		return;
	}

#if (defined(HAVE_SVA) & HAVE_SVA)
	else if ((q->dma_flag & VFIO_SPIMDEV_DMA_MULTI_PROC_MAP) &&
		 (q->pasid > 0)) {
		dma_unmap.pasid = q->pasid;
	}
#endif
	else if ((q->dma_flag & VFIO_SPIMDEV_DMA_SINGLE_PROC_MAP)) {
		;
	} else {
		WD_ERR("%s: dma flag error!\n", __func__);
		return;
	}
	size = ((size - 1) & _PAGE_MASK) + _PAGE_SIZE;
	dma_unmap.iova = (__u64)addr & _PAGE_MASK;
	dma_unmap.flags = 0;
	dma_unmap.size = size;
	dma_unmap.argsz = sizeof(dma_unmap);
	ioctl(q->container, VFIO_IOMMU_UNMAP_DMA, &dma_unmap);
}

int wd_mem_share(struct wd_queue *q, const void *addr, size_t size, int flags)
{
	if (drv_can_do_mem_share(q))
		return drv_share(q, addr, size, flags);
	else
		return _wd_mem_share_type1(q, addr, size, flags);
}

void wd_mem_unshare(struct wd_queue *q, const void *addr, size_t size)
{
	if (drv_can_do_mem_share(q))
		drv_unshare(q, addr, size);
	else
		_wd_mem_unshare_type1(q, addr, size);
}

