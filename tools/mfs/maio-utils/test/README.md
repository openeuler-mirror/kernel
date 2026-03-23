Here, we provide some strategies library for some cases.

- strategy_demo
A simple strategy library shows how to write a demo.

- strategy_prefetch
A prefetch strategy library to prefetch data.

- strategy_toend
A readahead strategy until the end.

- strategy_generate
A tools using maio-util to generate the io trace.

- strategy_replay
A strategy to replay the io trace.

### How to build

Using `make -j` to build the libraries.

### How to use

Set the library path as the `-s` parameter's value to run with maio-utils. Here we show usage of the advanced replay strategy:

- generate the io trace

> assume you have mounted the mfs at /mnt/mfs, and you are in build directory.

This is the tracing period.

```
export MAIO_TRACE_FILE=trace.txt
export MAIO_MNTPOINT=/mnt/mfs  # /mnt/mfs is the MFS mountpoint
./bin/maio-utils -m /mnt/mfs -s ../test/strategy_generate.so
```
Then, you can trigger the io. After finishing, you would get the trace file with the content likes:

```
xxx/model-00001-of-000008.safetensors 0 32768 0
xxx/model-00001-of-000008.safetensors 32768 32768 0
xxx/model-00001-of-000008.safetensors 65536 32768 0
xxx/model-00001-of-000008.safetensors 98304 32768 0
xxx/model-00001-of-000008.safetensors 131072 32768 0
...

```

The format is "<path> <offset> <length> <numaid>".

- replay the io trace

> assume you have mounted the mfs at /mnt/mfs and begin to launch the model.

This is the running period.

```
export MAIO_TRACE_FILE=trace.txt
export MAIO_MNTPOINT=/mnt/mfs  # /mnt/mfs is the MFS mountpoint
./bin/maio-utils -m /mnt/mfs -s ../test/strategy_replay.so
```
