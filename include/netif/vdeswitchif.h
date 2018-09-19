#ifndef __VDESWITCHIF_H__
#define __VDESWITCHIF_H__

struct netif;
struct event_base;

struct netif *vdeswitchif_add(struct event_base *base, const char *vde_name);

#endif
