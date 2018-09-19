#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>

#include <sys/time.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <net/if.h>

#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/ip.h>
#include <lwip/stats.h>
#include <lwip/init.h>
#include <lwip/snmp.h>
#include <lwip/etharp.h>
#include <netif/ethernet.h>

#include <event2/event.h>

#include "netif/tunif.h"

struct tunif_data {
	struct netif netif;
	int fd;
	int ether;
	struct event *ev;
	u_char buf[USHRT_MAX];
	char name[IFNAMSIZ];
};

static err_t
tunif_linkoutput(struct netif *netif, struct pbuf *p)
{
	struct tunif_data *data = netif->state;
	int len;

	len = pbuf_copy_partial(p, data->buf, sizeof(data->buf), 0);
	len = write(data->fd, data->buf, len);
	if (len < 0)
		LINK_STATS_INC(link.drop);
	else
		LINK_STATS_INC(link.xmit);

	return 0;
}

static err_t
tunif_output(struct netif *netif, struct pbuf *p, const ip_addr_t *ipaddr)
{
	return tunif_linkoutput(netif, p);
}

static void
tunif_ready(evutil_socket_t fd, short events, void *ctx)
{
	struct tunif_data *data = ctx;
	int ret;

	ret = read(fd, data->buf, sizeof(data->buf));
	if ((ret < 0 && errno != EAGAIN) || !ret) {
		/* FATAL */
		event_del(data->ev);
	} else if (ret > 0) {
		struct pbuf *p;
		p = pbuf_alloc(data->ether ? PBUF_LINK : PBUF_IP, ret, PBUF_RAM);
		if (!p) {
			LINK_STATS_INC(link.memerr);
			LINK_STATS_INC(link.drop);
			return;
		}
		LINK_STATS_INC(link.recv);
		pbuf_take(p, data->buf, ret);
		p->if_idx = netif_get_index(&data->netif);
		if (data->netif.input(p, &data->netif) < 0)
			pbuf_free(p);
	}
}

static err_t
tunif_init(struct netif *netif)
{
	struct tunif_data *data = netif->state;
	struct ifreq ifr;

	MIB2_INIT_NETIF(netif, snmp_ifType_other, 0);
	netif->name[0] = 't';
	netif->name[1] = data->ether ? 'a' : 'u';

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", data->name);

	ifr.ifr_mtu = netif->mtu;
	if (ioctl(data->fd, SIOCSIFMTU, &ifr) < 0) {
		close(data->fd);
		return -1;
	}

	netif->output = data->ether ? etharp_output : tunif_output;
	netif->linkoutput = data->ether ? tunif_linkoutput : NULL;
	netif->flags = NETIF_FLAG_LINK_UP;

	if (data->ether) {
		unsigned int seed = time(0);
		int i;
		
		/* Random HWADDR */
		for (i = 0; i < ETH_HWADDR_LEN; i++)
			netif->hwaddr[i] = rand_r(&seed);
		netif->hwaddr_len = ETH_HWADDR_LEN;
	} else {
		struct sockaddr_in addr;
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = netif->ip_addr.addr;
		memcpy(&ifr.ifr_dstaddr, &addr, sizeof(addr));
		if (ioctl(data->fd, SIOCSIFDSTADDR, &ifr) < 0) {
			close(data->fd);
			return -1;
		}
		
	}
	return 0;
}

struct netif *
tunif_add(struct event_base *base, const char *ifname, int ether)
{
	struct tunif_data *data;
	struct ifreq ifr;
	int fd;

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0)
		return NULL;

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);

	if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
		close(fd);
		return NULL;
	}

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		close(fd);
		return NULL;
	}

	data = calloc(1, sizeof(*data));

	evutil_make_socket_nonblocking(fd);

	data->ether = ether;
	data->fd = fd;
	data->ev = event_new(base, fd, EV_READ | EV_PERSIST, tunif_ready, data);
	snprintf(data->name, sizeof(data->name), "%s", ifname);
	event_add(data->ev, NULL);
	if (ether)
		data->netif.flags |= NETIF_FLAG_ETHARP | NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHERNET;
	netif_add(&data->netif, NULL, NULL, NULL, data, tunif_init, ether ? ethernet_input : ip_input);
	return &data->netif;
}
