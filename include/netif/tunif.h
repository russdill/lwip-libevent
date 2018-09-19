#ifndef __TUNIF_H__
#define __TUNIF_H__

struct netif;
struct event_base;

struct netif *tunif_add(struct event_base *base, const char *dev, int ether);

#endif
