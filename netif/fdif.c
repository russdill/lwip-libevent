#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <sys/time.h>

#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/stats.h>
#include <lwip/ip4.h>
#include <lwip/init.h>
#include <lwip/priv/tcp_priv.h>
#include <lwip/dns.h>
#include <lwip/snmp.h>
#include <lwip/etharp.h>
#include <netif/ethernet.h>

#include <event2/event.h>

#include "netif/fdif.h"

struct fdif_data {
	struct netif netif;
	int fd;
	int ether;
	struct event *ev;
	u_char buf[USHRT_MAX];
};

static err_t
fdif_linkoutput(struct netif *netif, struct pbuf *p)
{
	struct fdif_data *data = netif->state;
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
fdif_output(struct netif *netif, struct pbuf *p, const ip_addr_t *ipaddr)
{
	return fdif_linkoutput(netif, p);
}

static void
fdif_ready(evutil_socket_t fd, short events, void *ctx)
{
	struct fdif_data *data = ctx;
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
fdif_init(struct netif *netif)
{
	struct fdif_data *data = netif->state;

	MIB2_INIT_NETIF(netif, snmp_ifType_other, 0);
	netif->name[0] = 'f';
	netif->name[1] = 'd';

	netif->output = data->ether ? etharp_output : fdif_output;
	netif->linkoutput = data->ether ? fdif_linkoutput : NULL;
	netif->mtu = data->ether ? 1360 : 1360;
	netif->flags = NETIF_FLAG_LINK_UP;

	return 0;
}

struct netif *
fdif_add(struct event_base *base, int fd_in, int fd_out, int ether)
{
	struct fdif_data *data;

	data = calloc(1, sizeof(*data));

	evutil_make_socket_nonblocking(fd_in);
	evutil_make_socket_nonblocking(fd_out);

	data->ether = ether;
	data->fd = fd_out;
	data->ev = event_new(base, fd_in, EV_READ | EV_PERSIST, fdif_ready, data);
	event_add(data->ev, NULL);
	if (ether)
		data->netif.flags |= NETIF_FLAG_ETHARP | NETIF_FLAG_BROADCAST;
	netif_add(&data->netif, NULL, NULL, NULL, data, fdif_init, ether ? ethernet_input : ip_input);
	return &data->netif;
}
