#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>

#include <lwip/tcp.h>
#include <lwip/priv/tcp_priv.h>

#include "util/lwipevbuf.h"
#include "container_of.h"
#include "util/sockaddr.h"

static void
lwipevbuf_tcp_kill(struct lwipevbuf *bev)
{
	LWIP_DEBUGF(LWIPEVBUF_DEBUG, ("%s\n", __func__));
	if (bev->pcb) {
		tcp_arg(bev->pcb, NULL);
		tcp_err(bev->pcb, NULL);
		tcp_recv(bev->pcb, NULL);
		tcp_sent(bev->pcb, NULL);
		bev->pcb = NULL;
	}
	host_abort(&bev->hdata);
}

static void
lwipevbuf_process_refused(struct lwipevbuf *bev)
{
	if (bev->pcb && bev->pcb->refused_data) {
		LWIP_DEBUGF(LWIPEVBUF_INPUT_DEBUG, ("%s\n", __func__));
		if (bev->read_max) {
			size_t bytes = evbuffer_get_length(bev->input_buffer);
			struct pbuf *p = bev->pcb->refused_data;
			size_t extra = p->tot_len;
#if TCP_QUEUE_OOSEQ && LWIP_WND_SCALE
			if (p->next && extra > 64*1024) {
				/* lwIP will split packet with max size 64k */
				extra = 64*1024;
			}
#endif
			if (!bytes || bytes + extra <= bev->read_max) {
				tcp_process_refused_data(bev->pcb);
			}
		} else
			tcp_process_refused_data(bev->pcb);
	}
}

static void
lwipevbuf_inputcb(struct evbuffer *buffer,
			const struct evbuffer_cb_info *info, void *arg)
{
	struct lwipevbuf *bev = arg;
	size_t n_deleted = info->n_deleted;

	if (bev->input_push_offset >= 0)
		bev->input_push_offset -= info->n_deleted;

	LWIP_DEBUGF(LWIPEVBUF_INPUT_DEBUG, ("%s: n_deleted %ld, n_added %ld, pending %ld\n",
		__func__, info->n_deleted, info->n_added, bev->input_pending));

	/* Don't count initial bytes as part of tcp_recved */
	if (bev->input_pending >= n_deleted)
		bev->input_pending -= n_deleted;
	else {
		if (bev->input_pending) {
			n_deleted -= bev->input_pending;
			bev->input_pending = 0;
		}
		if (bev->pcb) {
			u16_t bytes;
			while (n_deleted) {
				if (n_deleted > UINT_MAX)
					bytes = 0xf000;
				else
					bytes = n_deleted;
				LWIP_DEBUGF(LWIPEVBUF_INPUT_DEBUG, ("%s: tcp_recved %u\n",
						__func__, bytes));
				tcp_recved(bev->pcb, bytes);
				n_deleted -= bytes;
			}
		}
	}

	lwipevbuf_process_refused(bev);
}

static void
lwipevbuf_process_output(struct lwipevbuf *bev)
{
	if (!bev->pcb)
		return;

	if (bev->pcb->state != ESTABLISHED && bev->pcb->state != CLOSE_WAIT &&
	    bev->pcb->state != SYN_SENT && bev->pcb->state != SYN_RCVD)
		return;

	LWIP_DEBUGF(LWIPEVBUF_OUTPUT_DEBUG, ("%s: %lu pending @%ld, %u avail\n", __func__,
			bev->output_pending, bev->output_start_at.pos, tcp_sndbuf(bev->pcb)));

	while (bev->output_pending) {
		struct evbuffer_iovec vec_out;
		size_t bytes;
		err_t ret;
		u8_t apiflags;
		tcpwnd_size_t sndbuf;
		int n;

		bytes = bev->output_pending;
		sndbuf = tcp_sndbuf(bev->pcb);
		if (!sndbuf)
			break;
		if (bytes > USHRT_MAX)
			bytes = USHRT_MAX;
		if (bytes > sndbuf)
			bytes = sndbuf;

		n = evbuffer_peek(bev->output_buffer, bytes,
					&bev->output_start_at, &vec_out, 1);
		if (!n)
			break;

		apiflags = 0;

		if (bytes > vec_out.iov_len)
			bytes = vec_out.iov_len;

		LWIP_DEBUGF(LWIPEVBUF_OUTPUT_DEBUG, ("%s: writing %lu bytes from %lu iovec @%ld\n", __func__,
			bytes, vec_out.iov_len, bev->output_start_at.pos));

		if (bev->output_push_offset < 0 || bev->output_start_at.pos + bytes < bev->output_push_offset) {
			LWIP_DEBUGF(LWIPEVBUF_OUTPUT_DEBUG, ("%s: more\n", __func__));
			apiflags |= TCP_WRITE_FLAG_MORE;
		}

		ret = tcp_write(bev->pcb, vec_out.iov_base, bytes, apiflags);
		if (ret == ERR_MEM) {
			/* Done reading for a while */
			LWIP_DEBUGF(LWIPEVBUF_OUTPUT_DEBUG, ("%s: ERR_MEM\n", __func__));
			break;
		} else if (ret < 0) {
			struct tcp_pcb *pcb = bev->pcb;
			LWIP_DEBUGF(LWIPEVBUF_OUTPUT_DEBUG, ("%s: err %d\n", __func__, ret));
			/* Kill connection */
			lwipevbuf_tcp_kill(bev);
			tcp_abort(pcb);
			bev->tcp_err = ret;
			if (bev->eventcb) {
				bev->hold++;
				bev->eventcb(bev, BEV_EVENT_ERROR|BEV_EVENT_WRITING, bev->ctx);
				bev->hold--;
				if (!bev->hold && bev->pending_free)
					free(bev);
			}
			break;
		} else {
			bev->output_pending -= bytes;
			evbuffer_ptr_set(bev->output_buffer, &bev->output_start_at, bytes, EVBUFFER_PTR_ADD);
		}
	}
}

static void
lwipevbuf_outputcb(struct evbuffer *buffer,
			const struct evbuffer_cb_info *info, void *arg)
{
	struct lwipevbuf *bev = arg;
	ssize_t pos = bev->output_start_at.pos;
	LWIP_DEBUGF(LWIPEVBUF_OUTPUT_DEBUG, ("%s: Adding/Draining %lu/%lu bytes. offset %lu orig_size %lu pending %lu\n",
		__func__, info->n_added, info->n_deleted, pos, info->orig_size, bev->output_pending));
	pos -= info->n_deleted;
	evbuffer_ptr_set(bev->output_buffer, &bev->output_start_at, pos, EVBUFFER_PTR_SET);
	bev->output_pending += info->n_added;

	lwipevbuf_process_output(bev);
}

/* Error on the tcp side */
static void
lwipevbuf_tcp_err(void *ctx, err_t err)
{
	struct lwipevbuf *bev = ctx;

	LWIP_DEBUGF(LWIPEVBUF_DEBUG, ("%s: %d\n", __func__, err));

	/* lwIP already freed the pcb */
	bev->pcb = NULL;

	switch (err) {
	case ERR_RST:
		break;
	case ERR_CLSD:
		/* From tcp_input_delayed_close */
		break;
	case ERR_ABRT:
		/* tcp_abandon/tcp_abort called when state != TIME_WAIT */
		break;
	default:
		break;
	}

	bev->tcp_err = err;
	if (bev->eventcb) {
		bev->hold++;
		bev->eventcb(bev, BEV_EVENT_ERROR, bev->ctx);
		bev->hold--;
		if (!bev->hold && bev->pending_free)
			free(bev);
	}
}

static void
lwipevbuf_cleanup_pbuf(const void *data, size_t datalen, void *extra)
{
	struct pbuf *curr = extra;
	LWIP_DEBUGF(LWIPEVBUF_INPUT_DEBUG, ("%s: %ld/%d bytes\n", __func__, datalen, curr->len));
	pbuf_free(curr);
}


static err_t
lwipevbuf_tcp_recv(void *ctx, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
	struct lwipevbuf *bev = ctx;
	struct pbuf *curr;
	err_t ret = ERR_OK;
	int first;

	if (!p) {
		LWIP_DEBUGF(LWIPEVBUF_INPUT_DEBUG, ("%s: EOF\n", __func__));
		if (bev->eventcb) {
			bev->hold++;
			bev->eventcb(bev, BEV_EVENT_EOF, bev->ctx);
			bev->hold--;
			if (bev->pending_free)
				ret = bev->pending_free;
			if (!bev->hold && bev->pending_free)
				free(bev);
		}
		return ret;
	}

	if (err < 0) {
		/* Note: Current versions always send ERR_OK here */
		LWIP_DEBUGF(LWIPEVBUF_INPUT_DEBUG, ("%s: Err %d\n", __func__, err));
		bev->tcp_err = err;
		if (bev->eventcb) {
			bev->hold++;
			bev->eventcb(bev, BEV_EVENT_ERROR, bev->ctx);
			bev->hold--;
			if (!bev->hold && bev->pending_free)
				free(bev);
		}
		return ERR_ABRT;
	}

	LWIP_DEBUGF(LWIPEVBUF_INPUT_DEBUG, ("%s: %d bytes\n", __func__, p->tot_len));

	if (bev->read_max) {
		size_t bytes = evbuffer_get_length(bev->input_buffer);
		if (bytes && bytes + p->tot_len > bev->read_max) {
			return ERR_WOULDBLOCK;
		}
	}

	/* input_buffer now owns pbuf, will free when drained or freed */
	first = 1;
	for (curr = p; curr; curr = curr->next) {
		LWIP_DEBUGF(LWIPEVBUF_INPUT_DEBUG, ("%s: ref %d bytes\n", __func__, curr->len));
		if (curr->len) {
			if (!first)
				pbuf_ref(curr);
			evbuffer_add_reference(bev->input_buffer, curr->payload,
				curr->len, lwipevbuf_cleanup_pbuf, curr);
		}
		first = 0;
	}

	if (!p->len)
		pbuf_free(p);

	if (p->flags & PBUF_FLAG_PUSH)
		bev->input_push_offset = evbuffer_get_length(bev->input_buffer);

	if (bev->readcb) {
		bev->hold++;
		bev->readcb(bev, bev->ctx);
		bev->hold--;
		if (bev->pending_free)
			ret = bev->pending_free;
		if (!bev->hold && bev->pending_free)
			free(bev);
	}
	return ret;
}

static err_t
lwipevbuf_tcp_sent(void *ctx, struct tcp_pcb *pcb, u16_t len)
{
	err_t ret = ERR_OK;
	if (len) {
		struct lwipevbuf *bev = ctx;
		/* Free memory no longer used by TCP */
		if (bev->output_push_offset >= 0)
			bev->output_push_offset -= len;
		LWIP_DEBUGF(LWIPEVBUF_OUTPUT_DEBUG, ("%s: Draining %u bytes, new offset %lu\n", __func__,
			len, bev->output_start_at.pos - len));
		evbuffer_drain(bev->output_buffer, len);
		if (bev->writecb) {
			bev->hold++;
			bev->writecb(bev, bev->ctx);
			bev->hold--;
			if (bev->pending_free)
				ret = bev->pending_free;
			if (!bev->hold && bev->pending_free)
				free(bev);
		}
	}

	return ret;
}

void
lwipevbuf_setcb(struct lwipevbuf *bev,
		void (*readcb)(struct lwipevbuf *, void *),
		void (*writecb)(struct lwipevbuf *, void *),
		void (*eventcb)(struct lwipevbuf *, short what, void *),
		void *ctx)
{
	bev->readcb = readcb;
	bev->writecb = writecb;
	bev->eventcb = eventcb;
	bev->ctx = ctx;
}

static err_t
lwipevbuf_connected(void *arg, struct tcp_pcb *pcb, err_t err)
{
	struct lwipevbuf *bev = arg;
	err_t ret = ERR_OK;
	LWIP_DEBUGF(LWIPEVBUF_DEBUG, ("%s\n", __func__));
	lwipevbuf_process_output(bev);
	if (bev->eventcb) {
		bev->hold++;
		bev->eventcb(bev, BEV_EVENT_CONNECTED, bev->ctx);
		bev->hold--;
		if (bev->pending_free)
			ret = bev->pending_free;
		if (!bev->hold && bev->pending_free)
			free(bev);
	}
	return ret;
}

void
lwipevbuf_output(struct lwipevbuf *bev)
{
	bev->output_push_offset = evbuffer_get_length(bev->output_buffer);
	if (!bev->output_push_offset)
		bev->output_push_offset = -1;
	LWIP_DEBUGF(LWIPEVBUF_OUTPUT_DEBUG, ("%s\n", __func__));
	if (bev->pcb == tcp_input_pcb)
		LWIP_DEBUGF(LWIPEVBUF_OUTPUT_DEBUG, ("%s: ignoring\n", __func__));
	tcp_output(bev->pcb);
}

int
lwipevbuf_connect(struct lwipevbuf *bev, const struct sockaddr *addr, int socklen)
{
	ip_addr_t remote_addr;
	int port;
	err_t err;

	if (sockaddr_to_ip_addr(addr, socklen, &remote_addr, &port) < 0)
		return ERR_ARG;

	err = tcp_connect(bev->pcb, &remote_addr, port, lwipevbuf_connected);
	if (err < 0) {
		bev->tcp_err = err;
		if (bev->eventcb) {
			bev->hold++;
			bev->eventcb(bev, BEV_EVENT_ERROR, bev->ctx);
			bev->hold--;
			if (!bev->hold && bev->pending_free)
				free(bev);
		}
	}
	return err;
}

static void
lwipevbuf_host_found(struct host_data *hdata)
{
	struct lwipevbuf *bev;
	err_t err;

	bev = container_of(hdata, struct lwipevbuf, hdata);

	err = tcp_connect(bev->pcb, &bev->hdata.ipaddr, bev->port, lwipevbuf_connected);
	if (err < 0) {
		bev->tcp_err = err;
		if (bev->eventcb) {
			bev->hold++;
			bev->eventcb(bev, BEV_EVENT_ERROR, bev->ctx);
			bev->hold--;
			if (!bev->hold && bev->pending_free)
				free(bev);
		}
	}
}

static void
lwipevbuf_host_failed(struct host_data *hdata, err_t err)
{
	struct lwipevbuf *bev;
	bev = container_of(hdata, struct lwipevbuf, hdata);

	bev->host_err = err;

	if (bev->eventcb) {
		bev->hold++;
		bev->eventcb(bev, BEV_EVENT_ERROR, bev->ctx);
		bev->hold--;
		if (!bev->hold && bev->pending_free)
			free(bev);
	}
}

int
lwipevbuf_connect_hostname(struct lwipevbuf *bev, int family,
						const char *hostname, int port)
{
	memset(&bev->hdata, 0, sizeof(bev->hdata));
	bev->hdata.found = lwipevbuf_host_found;
	bev->hdata.failed = lwipevbuf_host_failed;
	bev->port = port;
	strncpy(bev->hdata.fqdn, hostname, sizeof(bev->hdata.fqdn));
	if (bev->hdata.fqdn[sizeof(bev->hdata.fqdn) - 1])
		return ERR_ARG;
	host_lookup(&bev->hdata);
	return 0;
}

void
lwipevbuf_set_read_max(struct lwipevbuf *bev, size_t read_max)
{
	bev->read_max = read_max;
	lwipevbuf_process_refused(bev);
}

struct lwipevbuf *
lwipevbuf_new(struct tcp_pcb *pcb)
{
	struct lwipevbuf *bev;

	if (!pcb) {
		pcb = tcp_new();
		if (!pcb)
			return NULL;
	}

	bev = calloc(1, sizeof(*bev));

	bev->input_buffer = evbuffer_new();
	bev->output_buffer = evbuffer_new();
	bev->pcb = pcb;

	tcp_arg(bev->pcb, bev);
	tcp_err(bev->pcb, lwipevbuf_tcp_err);
	tcp_recv(bev->pcb, lwipevbuf_tcp_recv);
	tcp_sent(bev->pcb, lwipevbuf_tcp_sent);

	bev->outputcb = evbuffer_add_cb(bev->output_buffer, lwipevbuf_outputcb, bev);
	bev->inputcb = evbuffer_add_cb(bev->input_buffer, lwipevbuf_inputcb, bev);

	evbuffer_ptr_set(bev->output_buffer, &bev->output_start_at, 0, EVBUFFER_PTR_SET);

	bev->output_pending = evbuffer_get_length(bev->output_buffer);
	bev->input_pending = evbuffer_get_length(bev->input_buffer);
	bev->input_push_offset = -1;
	bev->output_push_offset = -1;

	lwipevbuf_process_output(bev);

	return bev;
}

void
lwipevbuf_free(struct lwipevbuf *bev)
{
	struct tcp_pcb *pcb = bev->pcb;
	err_t err = ERR_CLSD;

	LWIP_DEBUGF(LWIPEVBUF_DEBUG, ("%s\n", __func__));
	lwipevbuf_tcp_kill(bev);
	if (pcb) {
		size_t sndbuf = tcp_sndbuf(pcb);
		if (sndbuf != TCP_SND_BUF || tcp_close(pcb) < 0) {
			tcp_abort(pcb);
			err = ERR_ABRT;
		}
	}

	evbuffer_free(bev->input_buffer);
	bev->input_buffer = NULL;
	evbuffer_free(bev->output_buffer);
	bev->output_buffer = NULL;

	if (bev->hold)
		bev->pending_free = err;
	else
		free(bev);
}


