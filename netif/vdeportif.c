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

#include "libvdeplug_dyn.h"
#include "netif/vdeportif.h"

struct vdeportif_data {
	struct netif netif;
	struct vdepluglib vdeplug;
	VDECONN *vde;
	struct event *ev;
	char buf[4096];
};

static err_t
vdeportif_linkoutput(struct netif *netif, struct pbuf *p)
{
	struct vdeportif_data *data = netif->state;
	int len;

	len = pbuf_copy_partial(p, data->buf, sizeof(data->buf), 0);
	len = data->vdeplug.vde_send(data->vde, data->buf, len, 0);
	if (len < 0)
		LINK_STATS_INC(link.drop);
	else
		LINK_STATS_INC(link.xmit);

	return 0;
}

static void
vdeportif_ready(evutil_socket_t fd, short events, void *ctx)
{
	struct vdeportif_data *data = ctx;
	int ret;

	ret = data->vdeplug.vde_recv(data->vde, data->buf, sizeof(data->buf), 0);
	if (ret > 0) {
		struct pbuf *p;
		p = pbuf_alloc(PBUF_LINK, ret, PBUF_RAM);
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
vdeportif_init(struct netif *netif)
{
	MIB2_INIT_NETIF(netif, snmp_ifType_other, 0);
	netif->name[0] = 'v';
	netif->name[1] = 'p';

	netif->output = etharp_output;
	netif->linkoutput = vdeportif_linkoutput;
	netif->mtu = 1500;
	netif->flags = NETIF_FLAG_LINK_UP;

	return 0;
}

struct netif *
vdeportif_add(struct event_base *base, const char *vde_switch)
{
	struct vdeportif_data *data;

	data = calloc(1, sizeof(*data));

	libvdeplug_dynopen(data->vdeplug);
	if (!data->vdeplug.dl_handle) {
		free(data);
		return NULL;
	}

	data->vde = data->vdeplug.vde_open(vde_switch, "tunsocks", NULL);
	if (!data->vde) {
		free(data);
		return NULL;
	}

	data->ev = event_new(base, data->vdeplug.vde_datafd(data->vde),
			EV_READ | EV_PERSIST, vdeportif_ready, data);
	event_add(data->ev, NULL);
	data->netif.flags |= NETIF_FLAG_ETHARP | NETIF_FLAG_BROADCAST;
	netif_add(&data->netif, NULL, NULL, NULL, data, vdeportif_init, ethernet_input);

	return &data->netif;
}
