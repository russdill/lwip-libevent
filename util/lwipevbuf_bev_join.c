#include <stdlib.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/event.h>

#include <linux/tcp.h>

#include <lwip/tcp.h>

#include "util/lwipevbuf_bev_join.h"
#include "util/lwipevbuf.h"

static void
bufferevent_join_adjust_watermark(struct bufferevent *bev, struct lwipevbuf_bev_join_data *data)
{
	if (!data->b) {
		bufferevent_disable(bev, EV_READ);
	} else if (data->watermark) {
		ssize_t watermark;
		struct evbuffer *output;
		watermark = data->watermark;
		output = data->b->output_buffer;
		watermark -= evbuffer_get_length(output);
		if (watermark > 0) {
			bufferevent_setwatermark(bev, EV_READ, 0, watermark);
			bufferevent_enable(bev, EV_READ);
		} else
			bufferevent_disable(bev, EV_READ);
	}
}

static void
lwipevbuf_join_adjust_watermark(struct lwipevbuf *bev, struct lwipevbuf_bev_join_data *data)
{
	if (!data->a) {
		lwipevbuf_set_read_max(bev, 1);
	} else if (data->watermark) {
		ssize_t watermark;
		struct evbuffer *output;
		watermark = data->watermark;
		output = bufferevent_get_output(data->a);
		watermark -= evbuffer_get_length(output);
		if (watermark > 0) {
			lwipevbuf_set_read_max(bev, watermark);
		} else
			lwipevbuf_set_read_max(bev, 1);
	}
}

void
bufferevent_join_readcb(struct bufferevent *bev, void *ctx)
{
	struct lwipevbuf_bev_join_data *data = ctx;
	struct evbuffer *input = bufferevent_get_input(bev);

	if (data->flags & LWIPEVBUF_BEV_JOIN_B_TX_END) {
		/* Throw away input data */
		evbuffer_drain(input, evbuffer_get_length(input));
	} else {
		struct evbuffer *output;
		/*
		 * Note: There isn't a way to determine which packets have
		 * the push flag set under Linux.
		 */
		output = data->b->output_buffer;
		evbuffer_add_buffer(output, input);
		lwipevbuf_output(data->b);
	}

	bufferevent_join_adjust_watermark(bev, data);
}

void
lwipevbuf_join_readcb(struct lwipevbuf *bev, void *ctx)
{
	struct lwipevbuf_bev_join_data *data = ctx;
	struct evbuffer *input = bev->input_buffer;

	if (data->flags & LWIPEVBUF_BEV_JOIN_A_TX_END) {
		/* Throw away input data */
		evbuffer_drain(input, evbuffer_get_length(input));
	} else {
		ssize_t push_offset = bev->input_push_offset;
		if (push_offset >= 0)
			data->a_after_push = evbuffer_get_length(input) - push_offset;
		else if (data->a_after_push >= 0)
			data->a_after_push += evbuffer_get_length(input);
		bufferevent_write_buffer(data->a, input);
	}

	lwipevbuf_join_adjust_watermark(bev, data);
}

static int
bufferevent_join_destroy(struct bufferevent *bev, struct lwipevbuf_bev_join_data *data)
{
	LWIP_DEBUGF(LWIPEVBUF_BEV_JOIN_DEBUG, ("%s\n", __func__));
	bufferevent_setcb(bev, NULL, NULL, NULL, NULL);
	if (data->a_done)
		data->a_done(bev, data->a_ctx);
	else
		bufferevent_free(bev);
	data->a = NULL;
	if (!data->b) {
		LWIP_DEBUGF(LWIPEVBUF_BEV_JOIN_DEBUG, ("%s: all_done\n", __func__));
		if (data->all_done)
			data->all_done(data->all_ctx);
		free(data);
		return 1;
	}
	return 0;
}

static int
lwipevbuf_join_destroy(struct lwipevbuf *bev, struct lwipevbuf_bev_join_data *data)
{
	LWIP_DEBUGF(LWIPEVBUF_BEV_JOIN_DEBUG, ("%s\n", __func__));
	lwipevbuf_setcb(bev, NULL, NULL, NULL, NULL);
	if (data->b_done)
		data->b_done(bev, data->b_ctx);
	else
		lwipevbuf_free(bev);
	data->b = NULL;
	if (!data->a) {
		LWIP_DEBUGF(LWIPEVBUF_BEV_JOIN_DEBUG, ("%s: all_done\n", __func__));
		if (data->all_done)
			data->all_done(data->all_ctx);
		free(data);
		return 1;
	}
	return 0;
}

void
bufferevent_join_writecb(struct bufferevent *bev, void *ctx)
{
	struct lwipevbuf_bev_join_data *data = ctx;

	if (data->a_after_push >= 0) {
		struct evbuffer *output;
		int state;
		int fd = bufferevent_getfd(bev);
		output = bufferevent_get_output(data->a);
		if (data->a_after_push <= evbuffer_get_length(output)) {
			data->a_after_push = -1;
		}
		state = 1;
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &state, sizeof(state));
		state = 0;
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &state, sizeof(state));
	}


	if (data->b)
		lwipevbuf_join_adjust_watermark(data->b, data);

	if (data->flags & LWIPEVBUF_BEV_JOIN_B_RX_END) {
		if (!evbuffer_get_length(bufferevent_get_output(bev))) {
			LWIP_DEBUGF(LWIPEVBUF_BEV_JOIN_DEBUG, ("%s: A_TX_END\n", __func__));
			data->flags |= LWIPEVBUF_BEV_JOIN_A_TX_END;
			if (data->flags & LWIPEVBUF_BEV_JOIN_A_RX_END)
				bufferevent_join_destroy(bev, data);
		}
	}
}

void
lwipevbuf_join_writecb(struct lwipevbuf *bev, void *ctx)
{
	struct lwipevbuf_bev_join_data *data = ctx;
	if (data->a)
		bufferevent_join_adjust_watermark(data->a, data);

	if (data->flags & LWIPEVBUF_BEV_JOIN_A_RX_END) {
		if (!evbuffer_get_length(bev->output_buffer)) {
			LWIP_DEBUGF(LWIPEVBUF_BEV_JOIN_DEBUG, ("%s: B_TX_END\n", __func__));
			data->flags |= LWIPEVBUF_BEV_JOIN_B_TX_END;
			if (data->flags & LWIPEVBUF_BEV_JOIN_B_RX_END)
				lwipevbuf_join_destroy(bev, data);
		}
	}
}

void
bufferevent_join_eventcb(struct bufferevent *bev, short what, void *ctx)
{
	struct lwipevbuf_bev_join_data *data = ctx;
	size_t data_pending = 0;

	LWIP_DEBUGF(LWIPEVBUF_BEV_JOIN_DEBUG, ("%s: %04x\n", __func__, what));

	if (!(what & (BEV_EVENT_ERROR|BEV_EVENT_EOF)))
		return;

	if (data->b) {
		struct evbuffer *other_output;
		other_output = data->b->output_buffer;
		data_pending = evbuffer_get_length(other_output);
		LWIP_DEBUGF(LWIPEVBUF_BEV_JOIN_DEBUG, ("%s: pending %ld\n", __func__, data_pending));
	}

	data->flags |= LWIPEVBUF_BEV_JOIN_A_RX_END;
	if (what & BEV_EVENT_ERROR) {
		LWIP_DEBUGF(LWIPEVBUF_BEV_JOIN_DEBUG, ("%s: ERR\n", __func__));
		data->flags |= LWIPEVBUF_BEV_JOIN_A_TX_END;
		data->flags |= LWIPEVBUF_BEV_JOIN_B_RX_END;
		if (data->b) {
			tcp_shutdown(data->b->pcb, 1, 0);
			tcp_recv(data->b->pcb, NULL);
		}
	}

	if (data->flags & LWIPEVBUF_BEV_JOIN_A_TX_END)
		if (bufferevent_join_destroy(bev, data))
			return;

	if (!data_pending && data->b) {
		LWIP_DEBUGF(LWIPEVBUF_BEV_JOIN_DEBUG, ("%s: B_TX_END\n", __func__));
		data->flags |= LWIPEVBUF_BEV_JOIN_B_TX_END;
		if ((data->flags & LWIPEVBUF_BEV_JOIN_B_RX_END))
			lwipevbuf_join_destroy(data->b, data);
		else
			tcp_shutdown(data->b->pcb, 0, 1);
	}
}

void
lwipevbuf_join_eventcb(struct lwipevbuf *bev, short what, void *ctx)
{
	struct lwipevbuf_bev_join_data *data = ctx;
	int data_pending = 0;

	LWIP_DEBUGF(LWIPEVBUF_BEV_JOIN_DEBUG, ("%s: %04x\n", __func__, what));

	if (!(what & (BEV_EVENT_ERROR|BEV_EVENT_EOF)))
		return;

	if (data->a) {
		struct evbuffer *other_output;
		other_output = bufferevent_get_output(data->a);
		data_pending = evbuffer_get_length(other_output) != 0;
	}

	data->flags |= LWIPEVBUF_BEV_JOIN_B_RX_END;
	if (what & BEV_EVENT_ERROR) {
		LWIP_DEBUGF(LWIPEVBUF_BEV_JOIN_DEBUG, ("%s: ERR\n", __func__));
		data->flags |= LWIPEVBUF_BEV_JOIN_B_TX_END;
		data->flags |= LWIPEVBUF_BEV_JOIN_A_RX_END;
		if (data->a)
			bufferevent_disable(data->a, EV_READ);
	}

	if (data->flags & LWIPEVBUF_BEV_JOIN_B_TX_END)
		if (lwipevbuf_join_destroy(bev, data))
			return;

	if (!data_pending && data->a) {
		LWIP_DEBUGF(LWIPEVBUF_BEV_JOIN_DEBUG, ("%s: A_TX_END\n", __func__));
		data->flags |= LWIPEVBUF_BEV_JOIN_A_TX_END;
		if ((data->flags & LWIPEVBUF_BEV_JOIN_A_RX_END))
			bufferevent_join_destroy(data->a, data);
		else
			shutdown(bufferevent_getfd(data->a), SHUT_WR);
	}
}

void
lwipevbuf_bev_join(struct bufferevent *a, struct lwipevbuf *b,
		ssize_t watermark,
		void (*a_done)(struct bufferevent *bev, void *ctx), void *a_ctx,
		void (*b_done)(struct lwipevbuf *bev, void *ctx), void *b_ctx,
		void (*all_done)(void *ctx), void *ctx)
{
	struct lwipevbuf_bev_join_data *data;

	data = calloc(1, sizeof(*data));

	data->watermark = watermark;
	data->a = a;
	data->b = b;
	data->a_done = a_done;
	data->b_done = b_done;
	data->all_done = all_done;
	data->a_ctx = a_ctx;
	data->b_ctx = b_ctx;
	data->all_ctx = ctx;

	data->a_after_push = -1;

	bufferevent_setcb(a, bufferevent_join_readcb,
		bufferevent_join_writecb, bufferevent_join_eventcb, data);

	lwipevbuf_setcb(b, lwipevbuf_join_readcb,
		lwipevbuf_join_writecb, lwipevbuf_join_eventcb, data);

	bufferevent_set_timeouts(a, NULL, NULL);
	bufferevent_enable(a, EV_WRITE);

	if (!watermark) {
		bufferevent_setwatermark(a, EV_READ, 0, 0);
		bufferevent_enable(a, EV_READ);
		lwipevbuf_set_read_max(b, 0);
	}

	bufferevent_join_readcb(a, data);
	lwipevbuf_join_readcb(b, data);
}
