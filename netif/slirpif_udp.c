#include <lwip/inet_chksum.h>
#include <lwip/udp.h>
#include <event2/event.h>

#include "netif/slirpif.h"
#include "util/pbuf_iovec.h"
#include "util/sockaddr.h"
#include "container_of.h"

struct slirpif_udp_data {
	struct slirpif_data *data;
	struct event *ev;
	struct slirpif_udp_data *next;
	int idx;
	int fd;
	struct udp_pcb pcb;
};

#if LWIP_UDP
struct iovec udp_iov[256];

static void
udp_unlink(struct udp_pcb *pcb)
{
	struct udp_pcb *curr, **prev = &udp_pcbs;
	for (curr = udp_pcbs; curr; curr = curr->next) {
		if (curr == pcb) {
			*prev = curr->next;
			curr->next = NULL;
			break;
		}
		prev = &curr->next;
	}
}

static void
slirpif_udp_read(int fd, short what, void *ctx)
{
	struct slirpif_udp_data *udpdata = ctx;
	struct slirpif_data *data = udpdata->data;
	struct udp_pcb *pcb = &udpdata->pcb;

	slirpif_push(data);
	if (what & EV_TIMEOUT) {
		LWIP_DEBUGF(SLIRPIF_DEBUG, ("%s[%d]: UDP connection timed out\n", __func__, udpdata->idx));
		udp_unlink(pcb);
		event_free(udpdata->ev);
		close(udpdata->fd);
		free(udpdata);
	} else {
		int ret;
		static u8_t buf[USHRT_MAX];
		struct pbuf *p;

		ret = read(fd, buf, sizeof(buf));
		LWIP_DEBUGF(SLIRPIF_DEBUG, ("%s[%d]: Processing %d UDP bytes\n", __func__, udpdata->idx, ret));
		if (ret <= 0)
			goto done;
		p = pbuf_alloc(PBUF_TRANSPORT, ret, PBUF_RAM);
		if (!p)
			goto done;
		pbuf_take(p, buf, ret);
		udp_sendto_if_src(pcb, p, &pcb->remote_ip, pcb->remote_port,
						&data->remote, &pcb->local_ip);
		pbuf_free(p);
	}

done:
	slirpif_pop(data);
}

static void
slirpif_udp_recv(void *ctx, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *src, u16_t port)
{
	struct slirpif_udp_data *udpdata = ctx;
	LWIP_DEBUGF(SLIRPIF_DEBUG, ("%s[%d]: Forwarding %d UDP bytes\n", __func__, udpdata->idx, p->tot_len));
	pbuf_writev(udpdata->fd, p, udp_iov, LWIP_ARRAYSIZE(udp_iov));
	pbuf_free(p);
}

int
slirpif_output_udp(struct slirpif_data *data, struct pbuf *p,
		const ip_addr_t *src_addr, const ip_addr_t *dest_addr)
{
	struct udp_hdr *udphdr = (struct udp_hdr *) p->payload;
	u16_t src_port;
	u16_t dest_port;
	struct timeval tv;
	struct udp_pcb *pcb;
	struct slirpif_udp_data *udpdata;

	if (p->len < UDP_HLEN)
		return -1;

#if CHECKSUM_CHECK_UDP
	IF__NETIF_CHECKSUM_ENABLED(netif_get_by_index(p->if_idx), NETIF_CHECKSUM_CHECK_UDP) {
		if (udphdr->chksum != 0)
			if (ip_chksum_pseudo(p, IP_PROTO_UDP, p->tot_len,
					src_addr, dest_addr) != 0)
				return -1;
	}
#endif /* CHECKSUM_CHECK_UDP */

	src_port = lwip_ntohs(udphdr->src);
	dest_port = lwip_ntohs(udphdr->dest);

	LWIP_DEBUGF(SLIRPIF_DEBUG, ("%s: Processing outbound udp %08x:%d->%08x:%d\n", __func__,
			ip4_addr_get_u32(src_addr), src_port,
			ip4_addr_get_u32(dest_addr), dest_port));

	/* Look for an already associated pcb */
	for (pcb = udp_pcbs; pcb; pcb = pcb->next) {
		if (pcb->remote_port == dest_port &&
		    pcb->local_port == src_port &&
		    ip_addr_cmp(&pcb->remote_ip, dest_addr) &&
		    ip_addr_cmp(&pcb->local_ip, src_addr))
			break;
	}

	if (!pcb) {
		/* Need to generate a new one */
		struct sockaddr sa;
		socklen_t len;
		int fd;

		len = sizeof(sa);
		if (ip_addr_to_sockaddr(dest_addr, dest_port, &sa, &len) < 0)
			return -1;

		fd = socket(sa.sa_family, SOCK_DGRAM|SOCK_NONBLOCK, IPPROTO_UDP);
		if (fd < 0)
			return -1;

		if (connect(fd, &sa, len) < 0) {
			close(fd);
			return -1;
		}

		udpdata = calloc(1, sizeof(*udpdata));
		udpdata->fd = fd;
		udpdata->data = data;
		udpdata->idx = data->idx++;
		udpdata->ev = event_new(data->base, fd, EV_READ|EV_PERSIST, slirpif_udp_read, udpdata);

		pcb = &udpdata->pcb;
		pcb->ttl = UDP_TTL;
		ip_addr_set_ipaddr(&pcb->local_ip, dest_addr);
		pcb->local_port = dest_port;
		ip_addr_set_ipaddr(&pcb->remote_ip, src_addr);
		pcb->remote_port = src_port;
		pcb->flags |= UDP_FLAGS_CONNECTED;
		udp_bind_netif(pcb, &data->remote);
		udp_recv(pcb, slirpif_udp_recv, udpdata);
		pcb->next = udp_pcbs;
		udp_pcbs = pcb;
	} else
		udpdata = container_of(pcb, struct slirpif_udp_data, pcb);

	tv.tv_sec = 5 * 60; /* 5 minutes */
	tv.tv_usec = 0;
	event_add(udpdata->ev, &tv);

	return 0;
}
#endif

