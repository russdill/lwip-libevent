#ifndef __FDIF_H__
#define __FDIF_H__

#define NETIF_FLAG_BROADCAST    0x02U
#define NETIF_FLAG_POINTTOPOINT 0x04U

struct netif;
struct event_base;

struct netif *fdif_add(struct event_base *base, int fd_in, int fd_out, int ether);

#endif
