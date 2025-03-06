### About TrIO

On-demand loading of container images significantly improves container startup performance. However, compared to traditional full-image loading solutions, this method triggers many discrete network I/O operations during container runtime, which can introduce considerable overhead during the container's running phase. TrIO can be used to accelerate this scenario.

TrIO can be used to boost container startup based on Nydus, which is a typical container image on-demand loading solutions in container cases. It first tracks the I/O requests for reading image files during container runtime; the data corresponding to these I/O requests is the data needed for container running. Then, it orchestrates these I/O requests into the container's images and pushes them to the image repository. When a container is launched, TrIO can first pull these orchestrated I/O requests (referred to as I/O traces) to the local container node in the form of large I/O operations and use this data to reconstruct the rootfs required for container runtime. This rootfs will be used during container startup.

The core idea of TrIO is to aggregate I/O operations. It orchestrates the I/O operations actually used during container runtime into a single large I/O operation to pull all the required data to the container node in a single I/O, thereby reducing the network overhead associated with image fetching.

### Best Practice

The functionality of loading trace into the rootfs has already been implemented in the kernel, but the creation of trace requires coordination with user-space programs. In this case, we leverage the capabilities of eBPF to orchestrate the trace. Here are the files we will use in the following steps:

```shell
$ tree {KERNEL_TREE}/tools/trio/
├── bpf
│   ├── iotracker
│   │   ├── iotracker.bpf.c    # ebpf probe
│   │   ├── iotracker.c        # ebpf loading program
│   │   └── Makefile
│   └── rio_tracker_mod
│       ├── Makefile
│       └── rio_tracker.c      # provide the kfunc for probe
└── scripts
    └── trace_parser.py        # parse the raw trace
```

#### **Prerequisites**

- **kernel config**

If you want to enable TrIO, you should first compile the kernel with `CONFIG_EROFS_TRIO` enabled.

- **apply patch on nydus-snapshotter**

We assume that you have already set up the environment for on-demand container image loading and that you can successfully run the on-demand loading process for containers. To use TrIO, you can make some simple modifications to the snapshotter module of containerd. Here, we use `nydus-snapshotter-0.13.10` as an example for a brief explanation. Our goal is to make the functionality work, so we will make some simple adaptations within the snapshotter to fetch the I/O traces and load them into the kernel. The adaptation process can be as follow:

```shell
$ mkdir nydus-snapshotter-0.13.10/pkg/utils/trace
$ vim helper.go
```

In `helper.go` the content is:

```go
package trace

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
	"bufio"
	"strings"
)

const (
    BaseUrl       = "${trace_repo_url}"  // trace repo server, you can download traces from this url.   Such as http://10.67.175.82:8080
    LocalTraceDir = "${trace_repo_dir}"  // the directory where you download, Such as /home/trace-repo
)

func downloadCost(start time.Time, path string) {
	tc := time.Since(start)
	fmt.Printf("Downloading trace:%s cost = %v\n", path, tc)
}

func GetTraceHintFile() (string, string) {
	trace_hint := "/var/log/trace_hint"
	if _, err := os.Stat(trace_hint); os.IsNotExist(err) {
		return "", ""
	}
	file, err := os.Open(trace_hint)
	if err != nil {
		return "", ""
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	content, err := reader.ReadString('\n')
	if err != nil {
		return "", ""
	}
	content = strings.TrimSuffix(content, "\n")
	if len(content) == 0 {
		return "", ""
	}
	strArray := strings.Split(content, ",")
	return strArray[0], strArray[1]
}

func GetTraceHintPath() (string, string) {
	meta, data := GetTraceHintFile()
	if len(meta) == 0 || len(data) == 0 {
		return "", ""
	}
	real_meta := fmt.Sprintf("%s/%s", LocalTraceDir, meta)
	real_data := fmt.Sprintf("%s/%s", LocalTraceDir, data)
	return real_meta, real_data
}

func FetchTraceFile(filename string) string {
	localPath := fmt.Sprintf("%s/%s", LocalTraceDir, filename)
	finfo, err := os.Stat(localPath)
        if !os.IsNotExist(err) && finfo.Size() > 0 {
                return localPath
        }
	url := fmt.Sprintf("%s/%s", BaseUrl, filename)
	defer downloadCost(time.Now(), url)

	resp, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	/* create local file */
	file, err := os.Create(localPath)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	/* copy http file to local */
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		panic(err)
	}
	return localPath
}
```

> $trace_repo_url and $trace_repo_dir should be set.

In order the fetch I/O traces, we should add pulling logical in `snapshot/snapshot.go` . Here are the total changes:

```go
diff -Nuar -x bin ../nydus-snapshotter-0.13.10/pkg/daemon/daemon.go ./pkg/daemon/daemon.go
--- ../nydus-snapshotter-0.13.10/pkg/daemon/daemon.go	2024-03-19 09:30:29.000000000 +0800
+++ ./pkg/daemon/daemon.go	2025-02-21 19:36:29.208911094 +0800
@@ -20,6 +20,7 @@
 
 	"github.com/containerd/containerd/log"
 
+	"github.com/containerd/nydus-snapshotter/pkg/utils/trace"
 	"github.com/containerd/nydus-snapshotter/config"
 	"github.com/containerd/nydus-snapshotter/config/daemonconfig"
 	"github.com/containerd/nydus-snapshotter/pkg/daemon/types"
@@ -306,7 +307,9 @@
 	ra.AddAnnotation(rafs.AnnoFsCacheDomainID, cfg.DomainID)
 	ra.AddAnnotation(rafs.AnnoFsCacheID, fscacheID)
 
-	if err := erofs.Mount(cfg.DomainID, fscacheID, mountPoint); err != nil {
+
+	meta, data := trace.GetTraceHintPath()
+	if err := erofs.Mount(cfg.DomainID, fscacheID, meta, data, mountPoint); err != nil {
 		if !errdefs.IsErofsMounted(err) {
 			return errors.Wrapf(err, "mount erofs to %s", mountPoint)
 		}
diff -Nuar -x bin ../nydus-snapshotter-0.13.10/pkg/utils/erofs/erofs.go ./pkg/utils/erofs/erofs.go
--- ../nydus-snapshotter-0.13.10/pkg/utils/erofs/erofs.go	2024-03-19 09:30:29.000000000 +0800
+++ ./pkg/utils/erofs/erofs.go	2025-02-21 19:38:06.655911094 +0800
@@ -15,16 +15,21 @@
 	"golang.org/x/sys/unix"
 )
 
-func Mount(domainID, fscacheID, mountpoint string) error {
+func Mount(domainID, fscacheID, meta, data, mountpoint string) error {
 	mount := unix.Mount
 	var opts string
 
 	// Nydusd must have domain_id specified and it is set to fsid if it is
 	// never specified.
+	if meta != "" && data != "" {
+		opts = fmt.Sprintf("trio_meta=%s,trio_data=%s,", meta, data)
+	} else {
+		opts = ""
+	}
 	if domainID != "" && domainID != fscacheID {
-		opts = fmt.Sprintf("domain_id=%s,fsid=%s", domainID, fscacheID)
+		opts = fmt.Sprintf("%sdomain_id=%s,fsid=%s", opts, domainID, fscacheID)
 	} else {
-		opts = "fsid=" + fscacheID
+		opts = fmt.Sprintf("%sfsid=%s", opts, fscacheID)
 	}
 	log.L.Infof("Mount erofs to %s with options %s", mountpoint, opts)
 
diff -Nuar -x bin ../nydus-snapshotter-0.13.10/snapshot/process.go ./snapshot/process.go
--- ../nydus-snapshotter-0.13.10/snapshot/process.go	2024-03-19 09:30:29.000000000 +0800
+++ ./snapshot/process.go	2025-03-05 06:46:41.254104087 +0800
@@ -41,6 +41,7 @@
 
 	remoteHandler := func(id string, labels map[string]string) func() (bool, []mount.Mount, error) {
 		return func() (bool, []mount.Mount, error) {
+			sn.traceSync.Wait()
 			logger.Debugf("Prepare remote snapshot %s", id)
 			if err := sn.fs.Mount(ctx, id, labels, &s); err != nil {
 				return false, nil, err
diff -Nuar -x bin ../nydus-snapshotter-0.13.10/snapshot/snapshot.go ./snapshot/snapshot.go
--- ../nydus-snapshotter-0.13.10/snapshot/snapshot.go	2024-03-19 09:30:29.000000000 +0800
+++ ./snapshot/snapshot.go	2025-03-05 06:48:32.530104087 +0800
@@ -13,6 +13,7 @@
 	"os"
 	"path/filepath"
 	"strings"
+	"sync"
 
 	"github.com/pkg/errors"
 
@@ -26,6 +27,7 @@
 	"github.com/containerd/nydus-snapshotter/config"
 	"github.com/containerd/nydus-snapshotter/config/daemonconfig"
 
+	"github.com/containerd/nydus-snapshotter/pkg/utils/trace"
 	"github.com/containerd/nydus-snapshotter/pkg/cache"
 	"github.com/containerd/nydus-snapshotter/pkg/cgroup"
 	v2 "github.com/containerd/nydus-snapshotter/pkg/cgroup/v2"
@@ -58,6 +60,7 @@
 	enableKataVolume     bool
 	syncRemove           bool
 	cleanupOnClose       bool
+	traceSync            sync.WaitGroup
 }
 
 func NewSnapshotter(ctx context.Context, cfg *config.SnapshotterConfig) (snapshots.Snapshotter, error) {
@@ -293,6 +296,7 @@
 		enableNydusOverlayFS: cfg.SnapshotsConfig.EnableNydusOverlayFS,
 		enableKataVolume:     cfg.SnapshotsConfig.EnableKataVolume,
 		cleanupOnClose:       cfg.CleanupOnClose,
+		traceSync:	sync.WaitGroup{},
 	}, nil
 }
 
@@ -454,6 +458,17 @@
 	}
 
 	logger.Debugf("[Prepare] snapshot with labels %v", info.Labels)
+	if len(parent) == 0 {
+		o.traceSync.Add(1)
+		go func() {
+			defer o.traceSync.Done()
+			meta, data := trace.GetTraceHintFile()
+			if len(meta) != 0 && len(data) != 0 {
+				trace.FetchTraceFile(meta)
+				trace.FetchTraceFile(data)
+			}
+		}()
+	}
 
 	processor, target, err := chooseProcessor(ctx, logger, o, s, key, parent, info.Labels, func() string { return o.upperPath(s.ID) })
 	if err != nil {
@@ -492,6 +507,7 @@
 		// Nydusd might not be running. We should run nydusd to reflect the rootfs.
 		if err = o.fs.WaitUntilReady(pID); err != nil {
 			if errors.Is(err, errdefs.ErrNotFound) {
+				o.traceSync.Wait()
 				if err := o.fs.Mount(ctx, pID, pInfo.Labels, nil); err != nil {
 					return nil, errors.Wrapf(err, "mount rafs, instance id %s", pID)
 				}
@@ -522,6 +538,7 @@
 		if err != nil {
 			return nil, errors.Wrapf(err, "merge tarfs layers for snapshot %s", pID)
 		}
+		o.traceSync.Wait()
 		if err := o.fs.Mount(ctx, pID, pInfo.Labels, &s); err != nil {
 			return nil, errors.Wrapf(err, "mount tarfs, snapshot id %s", pID)
 		}
```

- **Trace Server**

Here we start an independent server to act as the server-side of the trace repository. In more formal way, the trace can be packed in the container images. For testing, the server only provides file download functionality.

```go
// trace_server.go
package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

func timeCost(start time.Time, path, action string) {
	tc := time.Since(start)
	fmt.Printf("%v file:%s cost = %v, at:%v\n", action, path, tc, time.Now().Format("2006-01-02 15:04:05.000"))
}

func download(w http.ResponseWriter, req *http.Request) {
	defer timeCost(time.Now(), req.RequestURI, "Downloading")

	filename := req.RequestURI[1:]
	enEscapeUrl, err := url.QueryUnescape(filename)
	if err != nil {
		w.Write([]byte(err.Error()))
		return
	}

	f, err := os.Open("./" + enEscapeUrl)
	if err != nil {
		w.Write([]byte(err.Error()))
		return
	}

	info, err := f.Stat()
	if err != nil {
		w.Write([]byte(err.Error()))
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))

	f.Seek(0, 0)
	io.Copy(w, f)
}

func main() {
	fmt.Printf("linsten on :8080 \n")
	http.HandleFunc("/", download)
	http.ListenAndServe(":8080", nil)
}
```



#### How to work

- **Track the runtime io for container**

> Notes: The container node for tracing can be different with running nodes.

###### Prepare

```shell
$ modprobe erofs; modprobe cachefiles;  # prepare nydus environment
$ cd $KERNEL_SRC/tools/trio/bpf/iotracker && make -j32; cd $KERNEL_SRC/tools/trio/bpf/rio_tracker_mod && make -j32
$ cd $KERNEL_SRC/tools/trio/bpf
$ insmod rio_tracker_mod/rio_tracker.ko tracker_output="/var/log/trace.txt"
$ iotracker/.output/iotracker
```

Now you have prepared the tracker environment. Then you should open a new terminal to prepare the following steps:

###### Tracker

```shell
$ sync; echo 1 > /proc/sys/vm/drop_caches; sleep 5
$ echo 4096 > /sys/kernel/debug/fault_around_bytes  # The original value should be keep, default 65536.
$ echo 1 > /sys/kernel/rio_tracker/reset
$ echo -n TRACE_HOST_NAME > /sys/kernel/rio_tracker/host_ns  # It will tracker the io in ${host_name} uts namespace. Here uts namespace is TRACE_HOST_NAME, it will be used when launch the container.
$ echo 1 > /sys/kernel/rio_tracker/enable
```

Then you just run your container task. Here we take running pytorch container in `Nydus` as an example:

- Terminal A:

  ```shell
  $ containerd-nydus-grpc --config /etc/nydus/config.toml --nydusd-config /etc/nydus/nydusd-config.fscache.json --fs-driver fscache --log-to-stdout
  ```

- Terminal B:

  ```shell
  $ nerdctl --snapshotter=nydus run -ti --hostname TRACE_HOST_NAME --rm --insecure-registry 10.67.175.82:5001/nydus/pytorch:nydus python -c "import datetime; print(datetime.datetime.now()); import torch;print(torch.cuda.is_available()); print(datetime.datetime.now())"  # If you want to run nginx, you may be like: nerdctl --snapshotter=nydus run --name test-nginx --hostname TRACE_HOST_NAME -p 9001:80 -d --insecure-registry 10.67.175.82:5001/nydus/nginx:nydus;./nginx_ok.sh
  ```

> Notes: You should launch the target container with `--hostname TRACE_HOST_NAME` which you used in the before step.

In our example, we launch a pytorch task with the output results. If you want trace the container which runs in backend (such as web services), Then after launching the container service, you should prepare the condition that serves the request. For network services (e.g., nginx, httpd), HTTP status OK is suitable for internal probes (this can trigger to load the necessary libraries). Such as:`curl -kv 127.0.0.1:9001`. So in our pytorch exmple, when the task finished, we stop tracing.

After the target condition is matched (finished), we can execute:

```shell
$ echo 0 > /sys/kernel/rio_tracker/enable
$ echo 65536 > /sys/kernel/debug/fault_around_bytes # recovery
$ echo 1 > /sys/kernel/rio_tracker/dump
```

Then your tracing about the target container task is finished. And the raw trace source is dumped at `/var/log/trace.txt`.

###### **Arrangement**

Launch the container again to obtain the rootfs (need run container in backend, such as `-d` flags), it is like:`/run/containerd/io.containerd.runtime.v2.task/default/${container_id}/rootfs` (You can see this by `df -h` command).

```shell
$ nerdctl --snapshotter=nydus run -d --insecure-registry 10.67.175.82:5001/nydus/pytorch:nydus sleep 999
$ df -h  # Then you can see the live rootfs
```

Then you can use the scripts `trace_parser.py` to process the traces.

```shell
$ cd $KERNEL_SRC/tools/trio/scripts
$ python3 trace_parser.py --trace_file=/var/log/trace.txt --output_dir=/var/log --root=${erofs root}  # such as python3 scripts/trace_parser.py --trace_file=/var/log/trace.txt --output_dir=/var/log --root=/home/containerd-root/containerd-nydus/snapshots/8/mnt
```

> erofs_root means the lowerdir of your container's rootfs

The output will show the trace data and metadata named as their `sha256` values. Then you can keep these trace files in the trace repository, here we can just use `scp` to transfer the traces to trace repository ( such as `scp /var/log/9af53bf836cc89591eb3f1df9a5302c5965c0049bb2622710a04519c06bd25c5 /var/log/fc8401b2850cc16d5850bf876543b85fd2b70fc5d112a846ca70e75a738cdbab root@10.67.175.82:/home/trace_hub`).

> Notes: In fact, I/O traces can be arraged into container images by modifying the container management tools. To achieve this, you need to modify the `nerdctl` and `containerd` packages.

- **Launch container by TrIO**

> Normally, the running node is different with the tracing node.

On the images or traces repository nodes (here is `10.67.175.82`), we can launch the traces server:

```shell
$ cd /home/trace_hub
$ go run trace_server.go
```

> Notes: the trace should be put into the same directory of `server.go`

Then on container node, we can start container. First, you should run container in on-demand loading mode. Take Nydus as example, we start nydus-snapshoter in one termimal, and run :

- Termimal A

  ```shell
  $ modprobe erofs; modprobe cachefiles;
  $ containerd-nydus-grpc --config /etc/nydus/config.toml --nydusd-config /etc/nydus/nydusd-config.fscache.json --fs-driver fscache --log-to-stdout
  ```

- Termimal B

```shell
$ echo "${trace_meta_name},${trace_data_name}" > /var/log/trace_hint     # such as echo "9af53bf836cc89591eb3f1df9a5302c5965c0049bb2622710a04519c06bd25c5,fc8401b2850cc16d5850bf876543b85fd2b70fc5d112a846ca70e75a738cdbab" > /var/log/trace_hint
$ nerdctl --snapshotter=nydus run -ti --rm --insecure-registry 10.67.175.82:5001/nydus/pytorch:nydus python -c "import datetime; print(datetime.datetime.now()); import torch;print(torch.cuda.is_available()); print(datetime.datetime.now())"
```

### Results

We conducted simple experiments on the following containers. By leveraging TrIO, we were able to significantly improve the startup performance of containers under on-demand loading scenarios.

|            | nginx   | redis   | tomcat   | pytorch   | tensorflow |
| ---------- | ------- | ------- | -------- | --------- | ---------- |
| Base       | 4.85 s  | 4.756 s | 10.026 s | 127.986 s | 35.164 s   |
| Nydus      | 3.136 s | 2.705 s | 6.794 s  | 19.136 s  | 29.931 s   |
| Nydus+TrIO | 2.873 s | 2.263 s | 4.954 s  | 6.814 s   | 8.496 s    |

