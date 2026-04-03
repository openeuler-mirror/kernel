#include "strategy_prefetch.h"
#include "maio.h"
#include <iostream>
#include <map>
#include <cstring>
#include <string>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

using namespace std;

struct prefetch_mgr {
    map<string, uint64_t> files;
};

struct prefetch_mgr g_prefetch;

int get_files(const char *parent)
{
    DIR *dir;
    struct dirent *entry;
    string filepath;
    struct stat buf;

    if ((dir = opendir(parent)) == NULL) {
        cout<<"opening directory failed"<<endl;
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        filepath = string(parent) + "/" + string(entry->d_name);
        if (stat(filepath.c_str(), &buf) == -1) {
            cout<<"stat path:"<<filepath<<" failed"<<endl;
            continue;
        }
        if (S_ISDIR(buf.st_mode))
            continue;
        cout<<"Find file:"<<filepath<<" size:"<<buf.st_size<<endl;
        g_prefetch.files.insert(pair<string, uint64_t>(filepath, buf.st_size));
    }

    map<string, uint64_t>::iterator it;
    for (it = g_prefetch.files.begin(); it != g_prefetch.files.end(); ++it) {
        cout<<"path:"<<it->first<<" size:"<<it->second<<endl;
    }
    return 0;
}

int prefetch_init(void)
{
    char *parent = getenv("MODEL_WEIGHT_DIR");
    if (!parent) {
        cout<<"please set the env MODEL_WEIGHT_DIR"<<endl;
        return -1;
    }

    if (get_files(parent) != 0) {
        cout<<"get all files failed"<<endl;
        return -1;
    }
    return 0;
}

void prefetch_exit(void)
{
}

struct thread_ctx {
    char *path;
    uint64_t off;
    uint64_t len;
};

void *fault(void *arg)
{
    struct thread_ctx *ctx = (struct thread_ctx *)arg;
    int fd = open(ctx->path, O_RDONLY);
    if (fd < 0) {
        cout<<"open file:%s"<<ctx->path<<" failed"<<endl;
        free(ctx);
        return NULL;
    }

    cout<<"FAULT path:"<<ctx->path<<" fd:"<<fd<<" off:"<<ctx->off<<" len:"<<ctx->len<<endl;
    void *addr = mmap(NULL, ctx->len, PROT_READ, MAP_SHARED, fd, 0);
    uint64_t idx;
    char tmp, total, *buffer = (char *)addr;
    total = 'B';
    for (idx = 0; idx < ctx->len; idx += 4096) {
        tmp = buffer[idx];
        total += tmp;
    }
    cout<<"Fault calculate total:"<<total<<endl;
    munmap(addr, ctx->len);
    close(fd);
    free(ctx);
    return NULL;
}

int prefetch_load(struct maio **io)
{
    map<string, uint64_t>::iterator it;
    struct thread_ctx *ctx;
    pthread_t t0;
    int ret;

    for (it = g_prefetch.files.begin(); it != g_prefetch.files.end(); ++it) {
        ctx = (struct thread_ctx *)malloc(sizeof(struct thread_ctx));
        if (!ctx) {
            cout<<"malloc ctx failed"<<endl;
            continue;
        }
        ctx->path = strdup(it->first.c_str());
        ctx->off = 0;
        ctx->len = it->second;
        ret = pthread_create(&t0, NULL, fault, ctx);
        if (ret == 0)
            pthread_detach(t0);
    }
    g_prefetch.files.clear();

    return 0;
}

int prefetch_evict(struct maio **io)
{
    ((void)io);
    return 0;
}

const struct maio_operation prefetch_strategy = {
        .max_io = 1,
        .init	= prefetch_init,
        .exit	= prefetch_exit,
        .load	= prefetch_load,
        .evict	= prefetch_evict,
};

struct maio_operation *register_strategy()
{
    return (struct maio_operation *)&prefetch_strategy;
}

