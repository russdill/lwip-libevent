#include <lwip/inet_chksum.h>
#include <lwip/tcp.h>
#include <lwip/priv/tcp_priv.h>

#include <event2/bufferevent.h>
#include <event2/event.h>

#include "netif/slirpif.h"
#include "util/sockaddr.h"

#include "util/lwipevbuf.h"
#include "util/lwipevbuf_bev_join.h"

struct slirpif_tcp_data {
	struct slirpif_data *data;
	struct slirpif_tcp_data *next;
	struct event *ev;
	struct pbuf *p;
	struct bufferevent *bev;
	struct tcp_pcb *lpcb;
	int idx;
	ip_addr_t client_ip;
	u16_t client_port;
};

#if LWIP_TCP
static void
slirpif_tcp_timeout(int fd, short what, void *ctx)
{
	struct slirpif_data *data = ctx;
	slirpif_push(data);
	/* Call tcp_fasttmr() every 250 ms */
	if (tcp_active_pcbs)
		tcp_fasttmr();

	if (++data->tcp_timer & 1) {
		/*
		 * Call tcp_slowtmr() every 500 ms, i.e., every other timer
		 * tcp_tmr() is called.
		 */
		tcp_slowtmr();
	}
	if (!tcp_active_pcbs && !tcp_tw_pcbs) {
		LWIP_DEBUGF(SLIRPIF_DEBUG, ("%s: Disabling\n", __func__));
		evtimer_del(data->timeout_ev);
	}
	slirpif_pop(data);
}

static void
slirpif_tcp_timer_needed(struct slirpif_data *data)
{
	if (!data->timeout_ev)
		data->timeout_ev = event_new(data->base, -1, EV_PERSIST, slirpif_tcp_timeout, data);
	if (!evtimer_pending(data->timeout_ev, NULL) && (tcp_active_pcbs || tcp_tw_pcbs)) {
		struct timeval interval;
		LWIP_DEBUGF(SLIRPIF_DEBUG, ("%s: Enabling\n", __func__));
		interval.tv_sec = TCP_TMR_INTERVAL / 1000;
		interval.tv_usec = (TCP_TMR_INTERVAL % 1000) * 1000;
		evtimer_add(data->timeout_ev, &interval);
	}
}

static void
slirpif_bev_wrap_readcb(struct bufferevent *bev, void *ctx)
{
	struct lwipevbuf_bev_join_data *arg = ctx;
	struct slirpif_data *data = arg->all_ctx;
	slirpif_push(data);
	bufferevent_join_readcb(bev, ctx);
	slirpif_pop(data);
}

static void
slirpif_bev_wrap_writecb(struct bufferevent *bev, void *ctx)
{
	struct lwipevbuf_bev_join_data *arg = ctx;
	struct slirpif_data *data = arg->all_ctx;
	slirpif_push(data);
	bufferevent_join_writecb(bev, ctx);
	slirpif_pop(data);
}

static void
slirpif_bev_wrap_eventcb(struct bufferevent *bev, short what, void *ctx)
{
	struct lwipevbuf_bev_join_data *arg = ctx;
	struct slirpif_data *data = arg->all_ctx;
	slirpif_push(data);
	bufferevent_join_eventcb(bev, what, ctx);
	slirpif_pop(data);
}


/* Caller of tcp_input has already pushed pcbs, will pop */
static err_t
slirpif_tcp_accept(void *ctx, struct tcp_pcb *pcb, err_t err)
{
	struct tcp_pcb *lpcb;
	struct lwipevbuf *lwipevbuf;
	struct slirpif_tcp_data *tcpdata, **prev;
	struct slirpif_data *data;
	struct bufferevent *bev;

	if (!pcb)
		/* client will either resend or we'll timeout */
		return ERR_ABRT;

	LWIP_DEBUGF(SLIRPIF_DEBUG, ("%s: %08x:%d->%08x:%d\n", __func__,
			ip4_addr_get_u32(&pcb->local_ip), pcb->local_port,
			ip4_addr_get_u32(&pcb->remote_ip), pcb->remote_port));
	
	prev = NULL;
	for (tcpdata = ctx; tcpdata; tcpdata = tcpdata->next) {
		LWIP_DEBUGF(SLIRPIF_DEBUG, ("%s[%d]: client %08x:%d\n", __func__,
				tcpdata->idx, ip4_addr_get_u32(&tcpdata->client_ip), tcpdata->client_port));
		if (tcpdata->client_port == pcb->remote_port &&
		    ip_addr_cmp(&tcpdata->client_ip, &pcb->remote_ip))
			break;
		prev = &tcpdata->next;
	}
	LWIP_ASSERT("Could not find tcpdata match in accept", tcpdata != NULL);

	LWIP_DEBUGF(SLIRPIF_DEBUG, ("%s[%d]: Connection complete\n", __func__, tcpdata->idx));
	lpcb = tcpdata->lpcb;
	data = tcpdata->data;
	slirpif_tcp_timer_needed(data);
	tcp_bind_netif(pcb, &data->remote);

	if (prev)
		*prev = tcpdata->next;
	else
		lpcb->callback_arg = tcpdata->next;
	if (tcpdata->p)
		pbuf_free(tcpdata->p);
	if (tcpdata->ev)
		event_free(tcpdata->ev);
	bev = tcpdata->bev;
	free(tcpdata);

	lwipevbuf = lwipevbuf_new(pcb);
	bufferevent_setcb(bev, NULL, NULL, NULL, NULL);
	bufferevent_set_timeouts(bev, NULL, NULL);
	lwipevbuf_bev_join(bev, lwipevbuf, 256*1024, NULL, NULL, NULL, NULL, NULL, data);

	/* Hijack callbacks so we can inject our tcp stack */
	bufferevent_getcb(bev, NULL, NULL, NULL, &ctx);
	bufferevent_setcb(bev, slirpif_bev_wrap_readcb, slirpif_bev_wrap_writecb,
						slirpif_bev_wrap_eventcb, ctx);

	/* Last one out frees lpcb */
	if (!lpcb->callback_arg)
		tcp_close(lpcb);

	return ERR_OK;
}

static void
slirpif_tcp_accept_timeout(int fd, short what, void *ctx)
{
	struct slirpif_tcp_data **prev, *curr, *tcpdata = ctx;
	struct tcp_pcb *lpcb = tcpdata->lpcb;
	struct slirpif_data *data = tcpdata->data;
	struct bufferevent *bev;
	struct pbuf *p;

	LWIP_DEBUGF(SLIRPIF_DEBUG, ("%s[%d]: Connection timed out\n", __func__, tcpdata->idx));
	p = tcpdata->p;
	tcpdata->p = NULL;
	bev = tcpdata->bev;
	tcpdata->bev = NULL;

	pbuf_free(p);
	bufferevent_setcb(bev, NULL, NULL, NULL, NULL);
	bufferevent_free(bev);
	if (tcpdata->ev)
		event_free(tcpdata->ev);

	prev = (struct slirpif_tcp_data **) &lpcb->callback_arg;
	for (curr = lpcb->callback_arg; curr; curr = curr->next) {
		if (tcpdata == curr)
			break;
		prev = &curr->next;
	}

	LWIP_ASSERT("Could not find tcpdata match in eventcb", curr != NULL);
	*prev = curr->next;
	free(tcpdata);

	/* Last user of associated lpcb turns out the lights */
	slirpif_push(data);
	if (!lpcb->callback_arg)
		tcp_close(lpcb);
	slirpif_pop(data);
}

#ifndef _WIN32
#define EVUTIL_ERR_CONNECT_REFUSED(e) ((e) == ECONNREFUSED)
#else
#define EVUTIL_ERR_CONNECT_REFUSED(e) ((e) == WSAECONNREFUSED)
#endif

static void
slirpif_bev_eventcb(struct bufferevent *bev, short what, void *ctx)
{
	struct tcp_pcb *lpcb = ctx;
	struct slirpif_tcp_data *tcpdata, **prev;
	struct slirpif_data *data;
	struct pbuf *p;

	prev = (struct slirpif_tcp_data **) &lpcb->callback_arg;
	for (tcpdata = lpcb->callback_arg; tcpdata; tcpdata = tcpdata->next) {
		if (tcpdata->bev == bev)
			break;
		prev = &tcpdata->next;
	}
	LWIP_ASSERT("Could not find tcpdata match in eventcb", tcpdata != NULL);

	p = tcpdata->p;
	tcpdata->p = NULL;

	data = tcpdata->data;
	slirpif_push(data);

	if (what & BEV_EVENT_CONNECTED) {
		struct timeval tv;
		/* Send syn packet (tcp_input will take ownership of pcb) */
		LWIP_DEBUGF(SLIRPIF_DEBUG, ("%s[%d]: Connection complete, injecting syn\n", __func__, tcpdata->idx));
		slirpif_enqueue(data, p, &data->remote);
		tcpdata->ev = evtimer_new(data->base, slirpif_tcp_accept_timeout, tcpdata);
		tv.tv_sec = 30;
		tv.tv_usec = 0; 
		evtimer_add(tcpdata->ev, &tv);
		bufferevent_setcb(bev, NULL, NULL, NULL, NULL);
		goto out;
	}

	LWIP_DEBUGF(SLIRPIF_DEBUG, ("%s[%d]: Connection failed %04x\n", __func__, tcpdata->idx, what));
	*prev = tcpdata->next;
	bufferevent_setcb(bev, NULL, NULL, NULL, NULL);
	bufferevent_free(bev);
	if (tcpdata->ev)
		event_free(tcpdata->ev);
	
	if (what & BEV_EVENT_ERROR) {
		int e = EVUTIL_SOCKET_ERROR();
		if (EVUTIL_ERR_CONNECT_REFUSED(e)) {
			const struct ip_hdr *iphdr = (const struct ip_hdr *) p->payload;
			u16_t iphdr_hlen = IPH_HL_BYTES(iphdr);
			struct tcp_hdr *tcphdr;
			pbuf_remove_header(p, iphdr_hlen);
			tcphdr = (struct tcp_hdr *) p->payload;
			u32_t ackno = lwip_ntohl(tcphdr->ackno);
			u32_t seqno = lwip_ntohl(tcphdr->seqno);
			u16_t tcplen = p->tot_len + 1;
			tcp_rst(lpcb, ackno, seqno + tcplen,
				&lpcb->local_ip, &tcpdata->client_ip,
				lpcb->local_port, tcpdata->client_port);
		}
	}

	if (p)
		pbuf_free(p);
	free(tcpdata);
	if (!lpcb->callback_arg)
		tcp_close(lpcb);

out:
	slirpif_pop(data);
}


int
slirpif_output_tcp(struct slirpif_data *data, struct pbuf *p,
		const ip_addr_t *src_addr, const ip_addr_t *dest_addr)
{
	struct tcp_hdr *tcphdr = (struct tcp_hdr *) p->payload;
	u16_t src_port;
	u16_t dest_port;
	struct slirpif_tcp_data *tcpdata;
	struct bufferevent *bev;
	struct sockaddr sa;
	struct tcp_pcb *lpcb;
	socklen_t len;
	u8_t flags;
	struct timeval tv;

	if (p->len < TCP_HLEN)
		return -1;

#if CHECKSUM_CHECK_TCP
	IF__NETIF_CHECKSUM_ENABLED(netif_get_by_index(p->if_idx), NETIF_CHECKSUM_CHECK_TCP) {
		if (ip_chksum_pseudo(p, IP_PROTO_TCP, p->tot_len,
				src_addr, dest_addr))
			return -1;
	}
#endif /* CHECKSUM_CHECK_TCP */

	dest_port = lwip_ntohs(tcphdr->dest);
	src_port = lwip_ntohs(tcphdr->src);
	LWIP_DEBUGF(SLIRPIF_DEBUG, ("%s: Processing outbound tcp %08x:%d->%08x:%d\n", __func__,
			ip4_addr_get_u32(src_addr), src_port,
			ip4_addr_get_u32(dest_addr), dest_port));

	flags = TCPH_FLAGS(tcphdr);
	if (!(flags & TCP_SYN) || flags & (TCP_RST | TCP_ACK)) {
		/*
		 * Not a new connection, handle normally.
		 *
		 * This packet just came from another interface or was locally
		 * generated by tcp_output. We switch over to our local tcp
		 * stack and inject it back into tcp_input which will generate
		 * data via the tcp_recv callback. That data will go out to the
		 * real destination and reply data may return.
		 *
		 * The reply data will be written to this pcb via tcp_write and
		 * then to tcp_output. tcp_output will locate a netif via
		 * tcp_route. Because we bound the pcb to our netif, it will
		 * be our netif and our output function will be called. We
		 * then switch back to the original tcp stack and inject it
		 * into our ip_input and it gets passed to the original
		 * generating pcb or forwarded back to the client.
		 */
		LWIP_DEBUGF(SLIRPIF_DEBUG, ("%s: Passing tcp packet\n", __func__));
		return 0; /* Send packet */
	}

	/* Find existing destination server */
	for (lpcb = tcp_listen_pcbs.pcbs; lpcb; lpcb = lpcb->next) {
		if (lpcb->local_port == dest_port &&
		    ip_addr_cmp(&lpcb->local_ip, dest_addr))
			break;
	}

	if (!lpcb) {
		/* None found, make a new listen pcb representing the dest */
		LWIP_DEBUGF(SLIRPIF_DEBUG, ("%s: New listener %08x:%d\n", __func__,
			ip4_addr_get_u32(dest_addr), dest_port));
		lpcb = tcp_new();
		if (!lpcb) {
			LWIP_DEBUGF(SLIRPIF_DEBUG, ("%s: tcp_new failed\n", __func__));
			return -1;
		}
		ip_addr_set_ipaddr(&lpcb->local_ip, dest_addr);
		lpcb->local_port = dest_port;
		ip_addr_set_ipaddr(&lpcb->remote_ip, src_addr);
		lpcb->remote_port = src_port;
		lpcb->state = LISTEN;
		tcp_backlog_set(lpcb, 10);
		tcp_accept(lpcb, slirpif_tcp_accept);
		TCP_REG(&tcp_listen_pcbs.pcbs, lpcb);
	}

	/* Find if already have an existing connection request pending */
	for (tcpdata = lpcb->callback_arg; tcpdata; tcpdata = tcpdata->next) {
		if (src_port == tcpdata->client_port &&
		    ip_addr_cmp(&tcpdata->client_ip, src_addr)) {
			if (tcpdata->p) {
				/* Get rid of the old pbuf (if present) */
		    		pbuf_free(tcpdata->p);
				tcpdata->p = NULL;
			}
			if (tcpdata->ev && evtimer_pending(tcpdata->ev, NULL)) {
				struct timeval tv;
				/* Accept is pending, send the new syn */
				LWIP_DEBUGF(SLIRPIF_DEBUG, ("%s[%d]: Forwarding updated syn\n", __func__, tcpdata->idx));
				/* Extend the timeout */
				tv.tv_sec = 30;
				tv.tv_usec = 0; 
				evtimer_add(tcpdata->ev, &tv);
				return 0; /* Send packet */
			} else {
				LWIP_DEBUGF(SLIRPIF_DEBUG, ("%s[%d]: Saving new syn\n", __func__, tcpdata->idx));
				tcpdata->p = p; /* Use the newer syn pbuf */
				return 1; /* Eat packet */
			}
		}
	}

	LWIP_DEBUGF(SLIRPIF_DEBUG, ("%s: New client %08x:%d\n", __func__,
			ip4_addr_get_u32(src_addr), src_port));

	/* New connection, start our outbound connection */
	len = sizeof(sa);
	if (ip_addr_to_sockaddr(dest_addr, dest_port, &sa, &len) < 0) {
		LWIP_DEBUGF(SLIRPIF_DEBUG, ("%s: Couldn't convert address\n", __func__));
		return -1;
	}
	bev = bufferevent_socket_new(data->base, -1, BEV_OPT_CLOSE_ON_FREE);
	if (bufferevent_socket_connect(bev, &sa, len) < 0) {
		LWIP_DEBUGF(SLIRPIF_DEBUG, ("%s: Couldn't create socket: %m\n", __func__));
		bufferevent_free(bev);
		return -1;	
	}
	tcpdata = calloc(1, sizeof(*tcpdata));
	tcpdata->data = data;
	tcpdata->idx = data->idx++;
	tcpdata->next = lpcb->callback_arg;
	lpcb->callback_arg = tcpdata;
	tcpdata->client_port = src_port;
	ip_addr_copy(tcpdata->client_ip, *src_addr);
	tcpdata->bev = bev;
	tcpdata->lpcb = lpcb;
	/* Store the syn packet so we can re-inject if the connection succeeds */
	tcpdata->p = p;
	tv.tv_sec = 30;
	tv.tv_usec = 0;
	bufferevent_set_timeouts(bev, &tv, NULL);
	bufferevent_enable(bev, EV_READ|EV_WRITE);
	bufferevent_setcb(bev, NULL, NULL, slirpif_bev_eventcb, lpcb);
	LWIP_DEBUGF(SLIRPIF_DEBUG, ("%s[%d]: Connecting to remote...\n", __func__, tcpdata->idx));

	return 1; /* Eat packet */
}
#endif

