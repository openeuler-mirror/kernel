#ifndef STRATEGY_TEMPLATE_H
#define STRATEGY_TEMPLATE_H

#ifdef __cplusplus
extern "C" {
#endif

int strategy_init(void);
void strategy_exit(void);
int strategy_load(struct maio **io);
int strategy_evict(struct maio *io);

extern const struct maio_operation maio_strategy;

struct maio_operation *register_strategy(void);

#ifdef __cplusplus
}
#endif

#endif
