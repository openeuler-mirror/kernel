# XSched 用户指南

## 1 环境部署

### 1.1 安装 NPU 原生软件栈

本特性依赖 NPU 原生软件栈，需要安装 NPU driver、firmware、CANN

### 1.2 安装XSched内核

#### 1.2.1 获取内核源码

```bash
# 下载源码
git clone https://atomgit.com/openeuler/kernel.git -b OLK-6.6 OLK-6.6

# 进入内核目录
cd OLK-6.6
```

#### 1.2.2 安装内核

##### 1.2.2.1 修改内核配置

```shell
# 生成默认配置
make openeuler_defconfig

# 修改并保存配置
vim .config

CONFIG_XCU_SCHEDULER=y
CONFIG_XCU_VSTREAM=y
CONFIG_XSCHED_NR_CUS=8 # 根据 NPU 卡的数量配置
CONFIG_XCU_SCHED_RT=y
CONFIG_XCU_SCHED_CFS=y
CONFIG_CGROUP_XCU=y
```

##### 1.2.2.2 编译安装

以下方式**二选一**：

* 源码编译安装

  ```bash
  make clean && make -j$(nproc)
  make modules_install -j$(nproc) INSTALL_MOD_STRIP=1 && INSTALL_MOD_STRIP=1 make install
  grub2-set-default 0
  ```

* RPM 包编译安装

  ```bash
  INSTALL_MOD_STRIP=1 make rpm-pkg -j `nproc`
  # kernel 和 devel 包都要安装，否则会导致驱动无法重编
  rpm -ivh <path_to_rpm> --force
  grub2-set-default 0
  ```

##### 1.2.2.3 修改 cmdline

```shell
# 修改内核引导文件，根据实际情况编辑
vim /etc/grub2-efi.cfg

# 在XSched内核新增 cmdline 配置，关闭驱动签名校验、开启cgroup-v2，使能 xcu cgroup 子系统
module.sig_enforce=0 cgroup_no_v1=all xcu=enable
```

保存引导文件后，重启切换内核，**注意！！！，xcu 子系统仅支持 cgroup-v2**

### 1.3 重编驱动

**！！需先安装好原生驱动！！**，`npu-smi info` 检查驱动是否安装成功

#### 1.3.1 修改驱动

获取驱动源码

```shell
mkdir <new_driver_dir>

./Ascend-hdk-910b-npu-driver_xx.x.x_linux-aarch64.run --tar -xvf -C <new_driver_dir>
```

下载驱动补丁 [XSched driver patch](https://gitcode.com/openeuler/kernel/commit/58e645cf8fd8d96573b7015385bf52522ebfee67?ref=refs/pull/18872/head&prId=18872) 适配 NPU 驱动

```shell
cp 0001-Adapt-910b-npu-driver-for-xsched.patch <new_driver_dir>/driver/kernel/
cd <new_driver_dir>/driver/kernel/

# 初始化 git 仓库并应用补丁
git init
git add .
git commit -m "npu init"
# 使用下载的 patch 文件
git am 58e645cf8fd8d96573b7015385bf52522ebfee67.patch --reject
# 如果有冲突则根据 .rej 文件适配冲突代码
git am drivers/xcu/0001-Adapt-910_93-npu-driver-for-xsched.txt --reject
```

#### 1.3.2 替换驱动

```shell
# 返回驱动根目录
cd ../../

# 备份原生驱动 ko
cp -r <new_driver_dir>/driver/host <new_driver_dir>/driver/host-bak
rm -f <new_driver_dir>/driver/host/*

cd <new_driver_dir>/driver/script
# 如果强制重编则增加 --force 参数，驱动 ko 会生成到 <new_driver_dir>/driver/host/
sh run_driver_ko_rebuild.sh [--force]

# 替换驱动
for line in `ls /lib/modules/$(uname -r)/updates`; do \cp ../host/$line /lib/modules/$(uname -r)/updates; done
```

#### 1.3.3 检查驱动

重启后检查驱动是否替换成功

```shell
reboot
npu-smi info
```

### 1.4 libXSched

XSched 用户态拦截层，拦截 CANN API 并转发到 XSched 内核

#### 1.4.1 编译

获取源码

```bash
git clone https://atomgit.com/openeuler/libXSched.git
```

编译源码

```bash
# 准备头文件
cp OLK-6.6/include/uapi/linux/xsched/xcu_vstream.h /usr/include/linux

# 编译生成 libucc_engine.so
make clean && make
```

#### 1.4.2 使用

使用 `LD_PRELOAD` 加载 `libucc_engine.so`

```bash
LD_PRELOAD=<path_to_libucc> <run_model_script>
```

### 1.5 验证

```shell
# 开启 XSched 日志
echo "file kernel/xsched/* +p" > /sys/kernel/debug/dynamic_debug/control

# pytorch 框架
LD_PRELOAD=<path_to_libucc> python3 -c "import torch;import torch_npu; a = torch.randn(3, 4).npu(); print(a + a);"

# mindspore 框架
LD_PRELOAD=<path_to_libucc> python3 -c "import mindspore;mindspore.set_device('Ascend');mindspore.run_check()"
```

`dmesg` 查看内核日志，检查是否有 XSCHED 日志，有日志则说明 XSched 环境部署成功，验证完后关闭 XSched 日志 `echo "file kernel/xsched/* -p" > /sys/kernel/debug/dynamic_debug/control`

## 2 使用指南

### 2.1 Cgroup 接口

#### 2.1.1 配置 XSched 策略

使能 XSched 控制器

```bash
echo "+xcu" > /sys/fs/cgroup/cgroup.subtree_control
```

##### 2.1.1.1 可配置接口

* `xcu.sched_class`：配置调度类，cfs 或 rt

* `xcu.period_ms`：配置获取算力资源时间片周期，默认 100ms（需先设置为 cfs 调度类）

* `xcu.quota_ms`：配置周期内可分配的时间片，比如配置 50ms，则每 100ms 内可分配 50ms，-1 则是不管控算力资源（需先设置为 cfs 调度类）

* `xcu.shares`：配置 cfs 任务的权重，权重越大，相比于其他任务的优先级越高，默认为 1024（需先设置为 cfs 调度类）

* `xcu.stat`：查看统计信息，仅支持 cfs 调度类

##### 2.1.1.2 Host 使用方法

在主机侧使用 XSched 管控 ai 任务，需手动创建 cgroup 组

```bash
mkdir -p /sys/fs/cgroup/xsched_group

# 按需配置 XSched 策略，例如 echo cfs > /sys/fs/cgroup/xsched_group/xcu.sched_class
echo <config_value> > /sys/fs/cgroup/xsched_group/xcu.<config_item>
```

将 ai 任务加入到 cgroup 中管控算力资源

```bash
# 运行 ai 任务
LD_PRELOAD=<path_to_libucc> <run_model_script>

# 加入 ai 任务到 cgroup
echo <pid> > /sys/fs/cgroup/xsched_group/cgroup.procs
```

##### 2.1.1.3 Docker 使用方法

启动 docker 容器时会自动挂载到 cgroup 目录（`/sys/fs/cgroup/user.slice`）下，docker 内的任务的 pid 也会自动添加到 cgroup.procs 下，无需手动创建 cgroup 组和添加任务

1. 修改 docker 配置，修改挂载的 cgroup 目录和 docker 的 cgroup 版本为 v2（**docker 需升级到支持 cgroup-v2 的版本**）

   ```bash
   vim /etc/docker/daemon.json

   # 添加以下配置
   # 挂载的 cgroup 目录，目录名任意，以 docker.slice 为例
   "cgroup-parent": "docker.slice"
   # 使用 cgroup-v2 管理 docker
   "exec-opts": ["native.cgroupdriver=systemd"]

   # 修改保存后重启 docker 服务
   systemctl restart docker
   ```

   因为 docker 默认的挂载目录是 `/sys/fs/cgroup/user.slice` ，`user.slice` 下还会有其他的用户任务在运行，可能会无法修改 `user.slice` 的 XSched 配置，所以需要修改 docker 的挂载目录为 `/sys/fs/cgroup/docker.slice` 方便配置和管理

2. 配置 docker 的 xsched 调度策略

   ```bash
   # 修改调度类为 cfs
   echo cfs > /sys/fs/cgroup/docker.slice/xcu.sched_class

   # 启动容器
   docker start <container_name>

   # 配置对应容器的 xsched 策略
   echo <config_value> > /sys/fs/cgroup/docker.slice/docker-<docker_id>/xcu.<config_item>

   # 进入容器
   docker exec -it <container_name> bash

   # 运行 ai 任务（容器内也有 libucc_engine.so），pid 会自动添加到 /sys/fs/cgroup/docker.slice/docker-<docker_id>/cgroup.procs
   LD_PRELOAD=<path_to_libucc> <run_model_script>
   ```

### 2.2 Syscall 接口

提供两个 syscall 接口用于设置/获取 rt 调度类的任务优先级（`xsched_setattr/xsched_getattr`）

* `pid`：ai 任务 pid，pid=0 表示当前进程

* `struct xsched_attr`：XSched 可配置属性

  ```c
  struct xsched_attr {
  	__u32 xsched_class; // 调度类，当前仅支持 RT（xsched_class=0）
  	__u32 xsched_priority; // rt 优先级，可配置范围 [1,5]，数字越大，优先级越高
  };
  ```

调用 syscall 接口示例程序：

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <sys/types.h>

// Define xsched_attr structure
struct xsched_attr {
	uint32_t xsched_class;     // Scheduling class: XSCHED_TYPE_RT, XSCHED_TYPE_CFS
	uint32_t xsched_priority;  // Priority level: 1~5
};

// Scheduling class constants (should match kernel header definitions)
#define XSCHED_TYPE_RT   0   // Real-time scheduling class
#define XSCHED_TYPE_CFS  1   // Completely Fair Scheduler class

// System call numbers (update these with actual numbers)
#define __NR_xsched_setattr 467
#define __NR_xsched_getattr 468

// Wrapper functions for system calls
static inline long xsched_setattr(pid_t pid, const struct xsched_attr *attr)
{
	return syscall(__NR_xsched_setattr, pid, attr);
}

static inline long xsched_getattr(pid_t pid, struct xsched_attr *attr)
{
	return syscall(__NR_xsched_getattr, pid, attr);
}

void main(void)
{
	pid_t pid = getpid();
	struct xsched_attr attr;
	long ret;

	// Get current configuration
	ret = xsched_getattr(pid, &attr);
	if (ret < 0) {
		printf("Failed to get configuration!\n");
	}

	attr.xsched_class = XSCHED_TYPE_RT;
	attr.xsched_priority = 3;

	ret = xsched_setattr(pid, &attr);
	if (ret < 0) {
		printf("Failed to set configuration\n");
	}

	// Verify the configuration
	memset(&attr, 0, sizeof(attr));
	ret = xsched_getattr(pid, &attr);
	if (ret < 0) {
		printf("Failed to verify configuration!\n");
	}
}
```

### 2.3 调试日志

开启/关闭 XSched 调试日志

```shell
echo "file kernel/xsched/* +p" > /sys/kernel/debug/dynamic_debug/control
echo "file kernel/xsched/* -p" > /sys/kernel/debug/dynamic_debug/control
```

开启/关闭 NPU 驱动调试日志

```shell
echo "module ascend_trs_core +p" > /sys/kernel/debug/dynamic_debug/control
echo "module ascend_trs_pm_adapt +p" > /sys/kernel/debug/dynamic_debug/control
echo "module ascend_trs_core -p" > /sys/kernel/debug/dynamic_debug/control
echo "module ascend_trs_pm_adapt -p" > /sys/kernel/debug/dynamic_debug/control
```
