# maio-utils

#### How to build

1. prepare thirdparty by using:
```
git clone -b threadpool_bind https://github.com/hb-lee/infrastructure.git infrastructure
git clone -b 1.2.18 https://github.com/HardySimpson/zlog.git thirdparty/zlog
git clone https://github.com/chriszt/securec.git thirdparty/securec
git clone -b v2.0.19 https://github.com/numactl/numactl.git thirdparty/libnuma
```
2. cd build
3. bash build.sh prepare  # only once.
4. bash build.sh build  # [debug|release]

#### How to run
Run with `./maio -m ${MNTPOINT}`, here ${MNTPOINT} means the mfs mount point. If you want to use some strategies, you can run with `./maio -m ${MNTPOINT} -s ${STRATEGYLIB}` where ${STRATEGYLIB} is your strategy library. Some examples are provided in `test` directory.
