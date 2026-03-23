#ifndef STRATEGY_PREFETCH_H
#define STRATEGY_PREFETCH_H

#ifdef __cplusplus
extern "C" {
#endif

int prefetch_init(void);
void prefetch_exit(void);
int prefetch_load(struct maio *io);
int prefetch_evict(struct maio **io);

extern const struct maio_operation prefetch_strategy;

struct maio_operation *register_strategy(void);

#ifdef __cplusplus
}
#endif

#endif
