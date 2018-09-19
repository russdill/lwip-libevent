#ifndef __UDPTAPIF_H__
#define __UDPTAPIF_H__

#include <lwip/opt.h>

#ifndef TAPNAT_DEBUG
#define TAPNAT_DEBUG LWIP_DBG_OFF
#endif

struct event_base;
struct netif;

struct netif *udptapif_add(struct event_base *base, unsigned short port_raw, unsigned short port_len);

#endif
