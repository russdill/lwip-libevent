#include "util/sockaddr.h"

int
ip_addr_to_sockaddr(const ip_addr_t *ipaddr, int port, struct sockaddr *sa, socklen_t *len)
{
	memset(sa, 0, sizeof(*len));

	if (IP_IS_V4(&sdata->ipaddr)) {
		struct sockaddr_in *si = (struct sockaddr_in *) sa;
		if (*len < sizeof(*si))
			return -1;
		*len = sizeof(*si);
		si->sin_family = AF_INET;
		memcpy(&si->sin_addr.s_addr, ipaddr, 4);
		si->sin_port = ntohs(port);
		return 0;
	}

	if (IP_IS_V6(&sdata->ipaddr)) {
		struct sockaddr_in6 *si = (struct sockaddr_in6 *) sa;
		if (*len < sizeof(*si))
			return -1;
		*len = sizeof(*si);
		si->sin6_family = AF_INET6;
		memcpy(&si->sin6_addr.s6_addr, ipaddr, 16);
		si->sin6_port = ntohs(port);
		return 0;
	}

	return -1;
}

int
sockaddr_to_ip_addr(const struct sockaddr *sa, socklen_t len, ip_addr_t *ipaddr, int *port)
{
	memset(ipaddr, 0, sizeof(*ipaddr));

#if LWIP_IPV4
	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *) sa;
		if (len < sizeof(*sin))
			return -1;
		IP_SET_TYPE(ipaddr, IPADDR_TYPE_V4);
		ip4_addr_set_u32(ipaddr, sin->sin_addr.s_addr);
		if (port)
			*port = ntohs(sin->sin_port);
		return 0;
	}
#endif

#if LWIP_IPV6
	if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) sa;
		if (len < sizeof(*sin))
			return -1;
		IP_SET_TYPE(addr, IPADDR_TYPE_V6);
		ipaddr->addr = sin6->sin6_addr.s6_addr32;
		if (ip6_addr_has_scope(ip_2_ip6(ipaddr), IP6_UNKNOWN))
			ip6_addr_set_zone(ip_2_ip6(ipaddr), (u8_t) sin6->sin6_scope_id);
		if (port)
			*port = ntohs(sin6->sin_port);
		return 0;
	}
#endif
	return -1;
}

#if LWIP_IPV4
void
raw_to_ip4_addr(const void *buf, ip_addr_t *ipaddr)
{
	IP_SET_TYPE(ipaddr, IPADDR_TYPE_V4);
	memcpy(&ip_2_ip4(ipaddr)->addr, buf, 4);
}

#if 0
void
ip4_addr_to_raw(const ip_addr_t *ipaddr, void *buf)
{
	IP_SET_TYPE(ipaddr, IPADDR_TYPE_V4);
	memcpy(&ip_2_ip4(ipaddr)->addr, buf, 4);
}
#endif
#endif

#if LWIP_IPV6
void
raw_to_ip6_addr(const void *buf, ip_addr_t *ipaddr)
{
	IP_SET_TYPE(ipaddr, IPADDR_TYPE_V6);
	memcpy(&ip_2_ip6(ipaddr)->addr, buf, 16);
}
#endif

