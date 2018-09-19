#ifndef __VDEPORTIF_H__
#define __VDEPORTIF_H__

struct netif;
struct event_base;

struct netif *vdeportif_add(struct event_base *base, const char *vde_name);

#endif
