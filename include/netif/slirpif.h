#ifndef __NETIF_SLIRPIF_H__
#define __NETIF_SLIRPIF_H__

#include <lwip/opt.h>
#include <lwip/ip.h>
#include <lwip/netif.h>

#ifndef SLIRPIF_DEBUG
#define SLIRPIF_DEBUG LWIP_DBG_OFF
#endif

struct event_base;
struct slirpif_data;
struct pbuf;
struct tcp_pcb;
struct udp_pcb;
struct ev;

struct slirpif_data {
	struct netif netif;
	struct pbuf *netif_queue[256];
	int netif_queue_n;
	struct netif remote;
	struct pbuf *remote_queue[256];
	int remote_queue_n;
	struct event_base *base;
	struct event *ev;
	int idx;
	int depth;

	struct netif *orig_netif_list;
	struct netif *orig_netif_default;
#if LWIP_TCP
	struct event *timeout_ev;
	u8_t tcp_timer;
	struct tcp_pcb *slirpif_tcp_bound_pcbs;
	struct tcp_pcb *slirpif_tcp_listen_pcbs;
	struct tcp_pcb *slirpif_tcp_active_pcbs;
	struct tcp_pcb *slirpif_tcp_tw_pcbs;
	u32_t slirpif_tcp_ticks;

	struct tcp_pcb *orig_tcp_bound_pcbs;
	struct tcp_pcb *orig_tcp_listen_pcbs;
	struct tcp_pcb *orig_tcp_active_pcbs;
	struct tcp_pcb *orig_tcp_tw_pcbs;
	u32_t orig_tcp_ticks;
#endif
#if LWIP_UDP
	struct udp_pcb *slirpif_udp_pcbs;
	struct udp_pcb *orig_udp_pcbs;
#endif
};

struct netif *slirpif_add(struct event_base *base);

void slirpif_push(struct slirpif_data *data);
void slirpif_pop(struct slirpif_data *data);
void slirpif_enqueue(struct slirpif_data *data, struct pbuf *p, struct netif *inp);
int slirpif_output_tcp(struct slirpif_data *data, struct pbuf *p,
		const ip_addr_t *src_addr, const ip_addr_t *dest_addr);
int slirpif_output_udp(struct slirpif_data *data, struct pbuf *p,
		const ip_addr_t *src_addr, const ip_addr_t *dest_addr);
		

#endif
