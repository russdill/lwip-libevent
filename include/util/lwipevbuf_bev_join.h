#ifndef __BUFFEREVENT_JOIN_H__
#define __BUFFEREVENT_JOIN_H__

#include <sys/types.h>

#ifndef LWIPEVBUF_BEV_JOIN_DEBUG
#define LWIPEVBUF_BEV_JOIN_DEBUG LWIP_DBG_OFF
#endif

struct bufferevent;
struct lwipevbuf;

#define LWIPEVBUF_BEV_JOIN_A_RX_END	1
#define LWIPEVBUF_BEV_JOIN_B_RX_END	2
#define LWIPEVBUF_BEV_JOIN_A_TX_END	4
#define LWIPEVBUF_BEV_JOIN_B_TX_END	8

struct lwipevbuf_bev_join_data {
	ssize_t watermark;
	struct bufferevent *a;
	struct lwipevbuf *b;
	int flags;
	ssize_t a_after_push;
	void (*a_done)(struct bufferevent *bev, void *ctx);
	void (*b_done)(struct lwipevbuf *bev, void *ctx);
	void (*all_done)(void *ctx);
	void *a_ctx;
	void *b_ctx;
	void *all_ctx;
};

void bufferevent_join_readcb(struct bufferevent *bev, void *ctx);
void lwipevbuf_join_readcb(struct lwipevbuf *bev, void *ctx);
void bufferevent_join_writecb(struct bufferevent *bev, void *ctx);
void lwipevbuf_join_writecb(struct lwipevbuf *bev, void *ctx);
void bufferevent_join_eventcb(struct bufferevent *bev, short what, void *ctx);
void lwipevbuf_join_eventcb(struct lwipevbuf *bev, short what, void *ctx);

void
lwipevbuf_bev_join(struct bufferevent *a, struct lwipevbuf *b,
		ssize_t watermark,
		void (*a_done)(struct bufferevent *bev, void *ctx), void *a_ctx,
		void (*b_done)(struct lwipevbuf *bev, void *ctx), void *b_ctx,
		void (*all_done)(void *ctx), void *ctx);

#endif
