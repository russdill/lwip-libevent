#ifndef __LWIPEVBUF_H__
#define __LWIPEVBUF_H__

#include <lwip/opt.h>

#include <sys/types.h>

#include <event2/buffer.h>

#include "util/host.h"

#ifndef LWIPEVBUF_OUTPUT_DEBUG
#define LWIPEVBUF_OUTPUT_DEBUG	LWIP_DBG_OFF
#endif
#ifndef LWIPEVBUF_INPUT_DEBUG
#define LWIPEVBUF_INPUT_DEBUG	LWIP_DBG_OFF
#endif
#ifndef LWIPEVBUF_DEBUG
#define LWIPEVBUF_DEBUG		LWIP_DBG_OFF
#endif

struct tcp_pcb;
struct evbuffer;
struct evbuffer_cb_entry;
struct sockaddr;
struct lwipevbuf;

struct lwipevbuf {
	struct tcp_pcb *pcb;
	int tcp_err;

	struct evbuffer *input_buffer;
	struct evbuffer *output_buffer;
	struct evbuffer_ptr output_start_at;
	size_t output_pending;
	size_t input_pending;
	size_t read_max;
	ssize_t output_push_offset;
	ssize_t input_push_offset;

	struct host_data hdata;
	int host_err;
	int port;

	struct evbuffer_cb_entry *outputcb;
	struct evbuffer_cb_entry *inputcb;

	void (*readcb)(struct lwipevbuf *, void *);
	void (*writecb)(struct lwipevbuf *, void *);
	void (*eventcb)(struct lwipevbuf *, short what, void *);
	void *ctx;

	int hold;
	int pending_free;
};

void lwipevbuf_setcb(struct lwipevbuf *bev,
		void (*readcb)(struct lwipevbuf *, void *),
		void (*writecb)(struct lwipevbuf *, void *),
		void (*eventcb)(struct lwipevbuf *, short what, void *),
		void *ctx);

void lwipevbuf_output(struct lwipevbuf *bev);
int lwipevbuf_connect(struct lwipevbuf *bev, const struct sockaddr *addr, int socklen);
int lwipevbuf_connect_hostname(struct lwipevbuf *bev, int family,
						const char *hostname, int port);
void lwipevbuf_set_read_max(struct lwipevbuf *bev, size_t read_max);
struct lwipevbuf *lwipevbuf_new(struct tcp_pcb *pcb);
void lwipevbuf_free(struct lwipevbuf *bev);

#endif
