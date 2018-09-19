#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/stats.h>
#include <lwip/init.h>
#include <lwip/snmp.h>
#include <lwip/etharp.h>
#include <netif/ethernet.h>

#include <event2/event.h>

#include "netif/udptapif.h"

#define HW_EXPIRE_TIME (60 * 60)

struct eth_client_hw {
	struct eth_addr addr;
	time_t expires;
};

struct eth_client;

struct eth_client {
	struct sockaddr_in ip;
	struct eth_client_hw *hw;
	int raw;
	int n;
	struct eth_client *next;
};

struct udptapif_data {
	struct netif netif;
	int fd_raw;
	int fd_len;
	struct event *ev_raw;
	struct event *ev_len;
	u_char buf[USHRT_MAX];
	struct eth_client *clients;
};

extern const struct eth_addr ethbroadcast;

static err_t
udptapif_linkoutput(struct netif *netif, struct pbuf *p)
{
	struct udptapif_data *data = netif->state;
	struct eth_addr dst = ethbroadcast;
	struct eth_client *client, **prev, *next;
	time_t now;
	int success = 0;
	int drop = 0;
	int bcast;
	int len;
	int ret;

	len = pbuf_copy_partial(p, data->buf + 2, sizeof(data->buf) - 2, 0);
	if (len >= sizeof(struct eth_hdr)) {
		struct eth_hdr *hdr = (struct eth_hdr *) (data->buf + 2);
		dst = hdr->dest;
	}

	*(unsigned short *)data->buf = htons(len);

	bcast = eth_addr_cmp(&dst, &ethbroadcast);

	LWIP_DEBUGF(TAPNAT_DEBUG, ("%s: Sending packet for %02x:%02x:%02x:%02x:%02x:%02x\n",
			__func__, dst.addr[0], dst.addr[1], dst.addr[2], dst.addr[3], dst.addr[4], dst.addr[5]));

	prev = &data->clients;
	now = time(0);
	for (client = data->clients; client; client = next) {
		int i;
		int active = 0;
		int match = bcast;
		next = client->next;

		for (i = 0; i < client->n; i++) {
			if (eth_addr_cmp(&dst, &client->hw[i].addr)) {
				client->hw[i].expires = now + HW_EXPIRE_TIME;
				match = 1;
			}
			if (client->hw[i].expires > now)
				active = 1;
		}
		if (!active) {
			LWIP_DEBUGF(TAPNAT_DEBUG, ("%s: Reaping client %s:%u\n", __func__,
					inet_ntoa(client->ip.sin_addr), ntohs(client->ip.sin_port)));
			*prev = next;
			free(client->hw);
			free(client);
		} else if (match) {
			LWIP_DEBUGF(TAPNAT_DEBUG, ("%s: Sending to client %s:%u\n", __func__,
					inet_ntoa(client->ip.sin_addr), ntohs(client->ip.sin_port)));
			if (client->raw)
				ret = sendto(data->fd_raw, data->buf + 2, len, 0,
						(struct sockaddr *) &client->ip,
						sizeof(client->ip));
			else
				ret = sendto(data->fd_len, data->buf, len + 2, 0,
						(struct sockaddr *) &client->ip,
						sizeof(client->ip));
			if (ret < 0)
				drop++;
			else
				success++;
		} else {
			LWIP_DEBUGF(TAPNAT_DEBUG, ("%s: Ignoring client %s:%u\n", __func__,
					inet_ntoa(client->ip.sin_addr), ntohs(client->ip.sin_port)));
		}

		prev = &client->next;
	}

	if (!success)
		LINK_STATS_INC(link.drop);
	else
		LINK_STATS_INC(link.xmit);

	return 0;
}

static void
udptapif_ready(evutil_socket_t fd, short events, void *ctx, int raw)
{
	struct udptapif_data *data = ctx;
	struct sockaddr_in addr;
	struct pbuf *p;
	struct eth_client *client;
	socklen_t addrlen = sizeof(addr);
	int ret;
	int len;
	unsigned char *buf;
	time_t now;

	ret = recvfrom(fd, data->buf, sizeof(data->buf), 0,
					(struct sockaddr *) &addr, &addrlen);
	if ((ret < 0 && errno != EAGAIN) || !ret) {
		/* FATAL */
		close(fd);
		if (raw) {
			event_del(data->ev_raw);
			event_free(data->ev_raw);
			data->ev_raw = NULL;
			data->fd_raw = -1;
		} else {
			event_del(data->ev_len);
			event_free(data->ev_len);
			data->ev_len = NULL;
			data->fd_len = -1;
		}
	} else if (ret < 0)
		return;

	if (raw) {
		len = ret;
		buf = data->buf;
	} else {
		if (ret < 2)
			return;
		len = ret - 2;
		buf = data->buf + 2;
	}

	p = pbuf_alloc(PBUF_LINK, len, PBUF_RAM);
	if (!p) {
		LINK_STATS_INC(link.memerr);
		LINK_STATS_INC(link.drop);
		return;
	}

	for (client = data->clients; client; client = client->next) {
		if (client->ip.sin_addr.s_addr == addr.sin_addr.s_addr &&
		    client->ip.sin_port == addr.sin_port && client->raw == raw)
			break;
	}
	if (!client) {
		client = calloc(1, sizeof(*client));
		client->ip = addr;
		client->n = 8;
		client->raw = raw;
		client->hw = calloc(client->n, sizeof(*client->hw));
		client->next = data->clients;
		data->clients = client;
	}

	LINK_STATS_INC(link.recv);
	pbuf_take(p, buf, len);

	if (len >= sizeof(struct eth_hdr)) {
		struct eth_hdr *hdr = (struct eth_hdr *) buf;
		int i;
		int free = -1;
		now = time(0);
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
	}

	LWIP_DEBUGF(TAPNAT_DEBUG, ("%s: Accepting packet, %d bytes\n", __func__, len));
	p->if_idx = netif_get_index(&data->netif);
	if (data->netif.input(p, &data->netif) < 0)
		pbuf_free(p);
}

static void
udptapif_ready_raw(evutil_socket_t fd, short events, void *ctx)
{
	udptapif_ready(fd, events, ctx, 1);
}

static void
udptapif_ready_len(evutil_socket_t fd, short events, void *ctx)
{
	udptapif_ready(fd, events, ctx, 0);
}

static err_t
udptapif_init(struct netif *netif)
{
	int i;
	unsigned int seed = time(0);

	MIB2_INIT_NETIF(netif, snmp_ifType_other, 0);
	netif->name[0] = 'u';
	netif->name[1] = 't';

	netif->output = etharp_output;
	netif->linkoutput = udptapif_linkoutput;
	netif->mtu = 1500;
	netif->flags = NETIF_FLAG_LINK_UP;
	netif->hwaddr_len = ETH_HWADDR_LEN;

	/* Random HWADDR */
	for (i = 0; i < ETH_HWADDR_LEN; i++)
		netif->hwaddr[i] = rand_r(&seed);

	netif->flags |= NETIF_FLAG_ETHARP | NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHERNET;
	return 0;
}

static int
udptapif_socket(unsigned short port)
{
	struct sockaddr_in addr;
	int fd;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	fd = socket(AF_INET, SOCK_DGRAM|SOCK_NONBLOCK, IPPROTO_UDP);
	if (fd < 0) {
		LWIP_DEBUGF(SOCKS_DEBUG, ("%s: socket %m\n", __func__));
		return -1;
	}

	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		LWIP_DEBUGF(SOCKS_DEBUG, ("%s: bind %m\n", __func__));
		close(fd);
		return -1;
	}

	return fd;
}

struct netif *
udptapif_add(struct event_base *base, unsigned short port_raw, unsigned short port_len)
{
	struct udptapif_data *data;

	data = calloc(1, sizeof(*data));

	if (port_raw) {
		data->fd_raw = udptapif_socket(port_raw);
		if (data->fd_raw < 0) {
			free(data);
			return NULL;
		}
		data->ev_raw = event_new(base, data->fd_raw, EV_READ|EV_PERSIST,
						udptapif_ready_raw, data);
		event_add(data->ev_raw, NULL);
	} else
		data->fd_raw = -1;

	if (port_len) {
		data->fd_len = udptapif_socket(port_len);
		if (data->fd_len < 0) {
			close(data->fd_raw);
			event_del(data->ev_raw);
			event_free(data->ev_raw);
			free(data);
			return NULL;
		}
		data->ev_len = event_new(base, data->fd_len, EV_READ|EV_PERSIST,
						udptapif_ready_len, data);
		event_add(data->ev_len, NULL);
	} else
		data->fd_len = -1;


	netif_add(&data->netif, NULL, NULL, NULL, data, udptapif_init, ethernet_input);

	return &data->netif;
}

