#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>

#include <sys/time.h>
#include <sys/un.h>
#include <sys/stat.h>

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
#include <event2/bufferevent.h>
#include <event2/listener.h>

#include "netif/vdeswitchif.h"

#define HW_EXPIRE_TIME (60 * 60)
#define SWITCH_MAGIC 0xfeedface

enum request_type { REQ_NEW_CONTROL, REQ_NEW_PORT0 };

struct vdeswitchif_client;

struct vdeswitchif_data {
	struct netif netif;
	struct evconnlistener *evl;
	char *vdepath;
	char buf[4096];
	struct vdeswitchif_client *clients;
};

struct vdeswitchif_client_hw {
	struct eth_addr addr;
	time_t expires;
};

struct vdeswitchif_client {
	int fd;
	int n;
	struct vdeswitchif_data *data;
	struct vdeswitchif_client_hw *hw;
	struct event *ev;
	struct bufferevent *bev;
	struct vdeswitchif_client *next;
};

struct request_v1 {
	uint32_t magic;
	enum request_type type;
	union {
		struct {
			unsigned char addr[6];
			struct sockaddr_un name;
		} new_control;
	} u;
	char description[];
} __attribute__((packed));

struct request_v3 {
	uint32_t magic;
	uint32_t version;
	enum request_type type;
	struct sockaddr_un sock;
	char description[];
} __attribute__((packed));

union request {
	struct request_v1 v1;
	struct request_v3 v3;
};

extern const struct eth_addr ethbroadcast;

static ssize_t
safe_read(int fd, void *buf, size_t count)
{
	ssize_t ret;
again:
	ret = read(fd, buf, count);
	if (ret < 0 && errno == EINTR)
		goto again;
	return ret;
}

static ssize_t
safe_write(int fd, const void *buf, size_t count)
{
	ssize_t ret;
again:
	ret = write(fd, buf, count);
	if (ret < 0 && errno == EINTR)
		goto again;
	return ret;
}

static void
vdeswitchif_client_free(struct vdeswitchif_client *client)
{
	if (client->ev)
		event_free(client->ev);
	if (client->fd >= 0)
		close(client->fd);

	bufferevent_free(client->bev);
	free(client->hw);
	free(client);
}

static void
vdeswitchif_client_remove(struct vdeswitchif_client *client)
{
	struct vdeswitchif_client *curr, **prev, *next;

	prev = &client->data->clients;
	for (curr = client->data->clients; curr; curr = next) {
		next = curr->next;
		if (curr == client) {
			*prev = next;
			break;
		}
	}

	vdeswitchif_client_free(client);
}

static err_t
vdeswitchif_linkoutput(struct netif *netif, struct pbuf *p)
{
	struct vdeswitchif_data *data = netif->state;
	struct vdeswitchif_client *client, **prev, *next;
	struct eth_hdr *hdr;
	int len;
	int ret;
	int bcast;
	time_t now;
	int drop = 0;
	int success = 0;

	len = pbuf_copy_partial(p, data->buf, sizeof(data->buf), 0);
	if (len < sizeof(struct eth_hdr)) {
		LINK_STATS_INC(link.drop);
		return 0;
	}

	hdr = (struct eth_hdr *) data->buf;
	bcast = eth_addr_cmp(&hdr->dest, &ethbroadcast);

	prev = &data->clients;
	now = time(0);
	for (client = data->clients; client; client = client->next) {
		int i;
		int active = 0;
		int match = bcast;

		next = client->next;

		for (i = 0; i < client->n; i++) {
			if (eth_addr_cmp(&hdr->dest, &client->hw[i].addr)) {
				client->hw[i].expires = now + HW_EXPIRE_TIME;
				match = 1;
			}
			if (client->hw[i].expires > now)
				active = 1;
		}

		if (!active) {
			*prev = next;
			vdeswitchif_client_free(client);
		} else if (match) {
			ret = safe_write(client->fd, data->buf, len);
			if (ret < 0) {
				drop++;
				*prev = next;
				vdeswitchif_client_free(client);
			} else
				success++;
		}

	}

	if (!success)
		LINK_STATS_INC(link.drop);
	else
		LINK_STATS_INC(link.xmit);

	return 0;
}

static void
vdeswitchif_ready(evutil_socket_t fd, short events, void *ctx)
{
	struct vdeswitchif_client *client = ctx;
	struct eth_hdr *hdr;
	struct pbuf *p;
	time_t now;
	int ret;
	int i;
	int free;

	ret = safe_read(fd, client->data->buf, sizeof(client->data->buf));
	if (ret <= 0) {
		vdeswitchif_client_remove(client);
		return;
	}

	if (ret < sizeof(struct eth_hdr)) {
		LINK_STATS_INC(link.drop);
		return;
	}

	hdr = (struct eth_hdr *) client->data->buf;
	now = time(0);
	free = -1;
	for (i = 0; i < client->n; i++) {
		if (eth_addr_cmp(&hdr->src, &client->hw[i].addr)) {
			client->hw[i].expires = now + HW_EXPIRE_TIME;
			break;
		}
		if (free == -1 && now > client->hw[i].expires)
			free = i;
	}
	if (i == client->n) {
		if (free == -1) {
			free = client->n;
			client->n *= 2;
			client->hw = reallocarray(client->hw, client->n, sizeof(*client->hw));
			memset(client->hw + free, 0, sizeof(*client->hw) * free);
		}
		client->hw[free].addr = hdr->src;
		client->hw[free].expires = now + HW_EXPIRE_TIME;
	}

	p = pbuf_alloc(PBUF_LINK, ret, PBUF_RAM);
	if (!p) {
		LINK_STATS_INC(link.memerr);
		LINK_STATS_INC(link.drop);
		return;
	}
	LINK_STATS_INC(link.recv);
	pbuf_take(p, client->data->buf, ret);
	p->if_idx = netif_get_index(&client->data->netif);
	if (client->data->netif.input(p, &client->data->netif) < 0)
		pbuf_free(p);
}

static void
vdeswitchif_bev_error(struct bufferevent *bev, short events, void *ctx)
{
	vdeswitchif_client_remove(ctx);
}

static void
vdeswitchif_bev_readable(struct bufferevent *bev, void *ctx)
{
	struct vdeswitchif_client *client = ctx;
	struct event_base *base = bufferevent_get_base(bev);
	union request *req;
	struct sockaddr_un sun;
	struct sockaddr_un *addr;
	int ret;
	enum request_type type;

	memset(client->data->buf, 0, sizeof(client->data->buf));
	ret = bufferevent_read(bev, client->data->buf, sizeof(client->data->buf)-1);
	if (ret <= 0)
		return;

	req = (union request *) client->data->buf;
	if (req->v1.magic != SWITCH_MAGIC) {
		goto err;
	}

	if (req->v3.version == 3) {
		type = req->v3.type;
		addr = &req->v3.sock;
	} else if (req->v3.version < 2) {
		type = req->v1.type;
		addr = &req->v1.u.new_control.name;
	} else {
		goto err;
	}

	if (type != REQ_NEW_PORT0 && type != REQ_NEW_CONTROL)
		goto err;

	client->fd = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (client->fd < 0)
		goto err;

	evutil_make_socket_nonblocking(client->fd);

	if (connect(client->fd, addr, sizeof(struct sockaddr_un)) < 0)
		goto err;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	snprintf(sun.sun_path, sizeof(sun.sun_path), "%s/000.%d", client->data->vdepath, client->fd);
	if (unlink(sun.sun_path) < 0 && errno != ENOENT)
		goto err;

	if (bind(client->fd, (struct sockaddr *) &sun, sizeof(struct sockaddr_un)) < 0)
		goto err;

	bufferevent_write(bev, &sun, sizeof(sun));

	client->ev = event_new(base, client->fd, EV_READ | EV_PERSIST, vdeswitchif_ready, client);
	event_add(client->ev, NULL);

	client->next = client->data->clients;
	client->data->clients = client;

	bufferevent_disable(bev, EV_READ);
	return;

err:
	vdeswitchif_client_free(client);
}

static void
vdeswitchif_accept(struct evconnlistener *evl, evutil_socket_t new_fd,
			struct sockaddr *addr, int socklen, void *ctx)
{
	struct event_base *base = evconnlistener_get_base(evl);
	struct vdeswitchif_data *data = ctx;
	struct vdeswitchif_client *client = ctx;

	client = calloc(1, sizeof(*client));

	client->data = data;
	client->fd = -1;
	client->n = 8;
	client->hw = calloc(client->n, sizeof(*client->hw));
	client->bev = bufferevent_socket_new(base, new_fd, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(client->bev, vdeswitchif_bev_readable,
			NULL, vdeswitchif_bev_error, client);
	bufferevent_enable(client->bev, EV_READ);
	bufferevent_set_timeouts(client->bev, NULL, NULL);
	vdeswitchif_bev_readable(client->bev, client);
}

static err_t
vdeswitchif_init(struct netif *netif)
{
	MIB2_INIT_NETIF(netif, snmp_ifType_other, 0);
	netif->name[0] = 'v';
	netif->name[1] = 's';

	netif->output = etharp_output;
	netif->linkoutput = vdeswitchif_linkoutput;
	netif->mtu = 1500;
	netif->flags = NETIF_FLAG_LINK_UP;

	return 0;
}

struct netif *
vdeswitchif_add(struct event_base *base, const char *vde_switch)
{
	struct vdeswitchif_data *data;
	struct sockaddr_un sun;

	if (mkdir(vde_switch, 0777) < 0 && errno != EEXIST)
		return NULL;

	data = calloc(1, sizeof(*data));
	data->vdepath = realpath(vde_switch, NULL);
	if (!data->vdepath) {
		free(data);
		return NULL;
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	snprintf(sun.sun_path, sizeof(sun.sun_path), "%s/ctl", data->vdepath);

	data->evl = evconnlistener_new_bind(base, vdeswitchif_accept, data,
		LEV_OPT_CLOSE_ON_FREE | LEV_OPT_CLOSE_ON_EXEC |
		LEV_OPT_REUSEABLE, 10,
		(struct sockaddr *) &sun, sizeof(&sun));
	if (!data->evl) {
		free(data->vdepath);
		free(data);
		return NULL;
	}
	data->netif.flags |= NETIF_FLAG_ETHARP | NETIF_FLAG_BROADCAST;
	netif_add(&data->netif, NULL, NULL, NULL, data, vdeswitchif_init, ethernet_input);

	return &data->netif;
}
