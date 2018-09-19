#ifndef __NETTEST_H__
#define __NETTEST_H__

struct netif;

int nettest_add(struct event_base *base, struct netif *netif, unsigned int delay_us, float drop_rate);
void nettest_remove(struct netif *netif);

#endif
