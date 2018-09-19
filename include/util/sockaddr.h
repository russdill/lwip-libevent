#ifndef __SOCKADDR_H__
#define __SOCKADDR_H__

#include <lwip/ip_addr.h>
#include <sys/socket.h>
#include <netinet/in.h>

int
ip_addr_to_sockaddr(const ip_addr_t *ipaddr, int port, struct sockaddr *sa, socklen_t *len);

int
sockaddr_to_ip_addr(const struct sockaddr *sa, socklen_t len, ip_addr_t *ipaddr, int *port);

#if LWIP_IPV4
void
raw_to_ip4_addr(const void *buf, ip_addr_t *ipaddr);
#endif

#if LWIP_IPV6
void
raw_to_ip6_addr(const void *buf, ip_addr_t *ipaddr);
#endif

#endif
