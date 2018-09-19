#include <sys/time.h>
#include <time.h>

#include <event2/event.h>

#include <lwip/netif.h>
#include <lwip/pbuf.h>

#include "util/nettest.h"

enum nettest_action {
	NETTEST_INPUT,
	NETTEST_OUTPUT,
	NETTEST_OUTPUT_IP6,
	NETTEST_LINKOUTPUT,
};

struct nettest_elem {
	struct pbuf *p;
	struct timeval expires;
	struct netif *netif;
	ip_addr_t addr;
	enum nettest_action action;
};

struct nettest_entry {
	struct nettest_elem elems[256];
	unsigned int head, tail;
	struct nettest_entry *next;
};

struct nettest_data {
	netif_input_fn orig_input;
#if LWIP_IPV4
	netif_output_fn orig_output;
#endif /* LWIP_IPV4*/
#if LWIP_IPV6
	netif_output_ip6_fn orig_output_ip6;
#endif /* LWIP_IPV6 */
	netif_linkoutput_fn orig_linkoutput;

	struct event *ev;
	struct nettest_entry *queue_head;
	struct nettest_entry *queue_tail;
	struct timeval delay;
	unsigned int seed;
	unsigned int drop;
	int drop_all;
};

static struct nettest_data nettest_data[256];
static struct nettest_entry *queue_free;

static void
nettest_schedule(struct nettest_data *data, struct nettest_elem *elem)
{
     	struct timeval tv;
	struct timespec now;

	clock_gettime(CLOCK_BOOTTIME, &now);

	/* libevent timeval has granularity of 1us */
	now.tv_nsec /= 1000;

     	tv.tv_sec = elem->expires.tv_sec - now.tv_sec;
     	if (now.tv_nsec > elem->expires.tv_usec) {
     		tv.tv_sec--;
     		elem->expires.tv_usec += 1000000;
     	}
     	tv.tv_usec = elem->expires.tv_usec - now.tv_nsec;
     	evtimer_add(data->ev, &tv);
}

static struct nettest_elem *
nettest_enqueue(struct nettest_data *data, struct pbuf *p, struct netif *netif)
{
	struct nettest_entry *entry;
	struct nettest_elem *elem;
	struct timespec now;

	entry = data->queue_tail;
	if (!entry || entry->tail == 256) {
		/* Current entry full (or absent), get a new one */
		if (queue_free) {
			/* Pull from free list */
			entry = queue_free;
			queue_free = entry->next;
			entry->tail = entry->head = 0;
			entry->next = NULL;
		} else
			entry = calloc(1, sizeof(*entry));
		if (data->queue_tail)
			data->queue_tail->next = entry;
		data->queue_tail = entry;
		if (!data->queue_head)
			data->queue_head = entry;
	}

	elem = entry->elems + entry->tail++;

	elem->p = p;
	elem->netif = netif;
	clock_gettime(CLOCK_BOOTTIME, &now);

	/* libevent timeval has granularity of 1us */
	now.tv_nsec /= 1000;

	elem->expires.tv_sec = now.tv_sec + data->delay.tv_sec;
	elem->expires.tv_usec = now.tv_nsec + data->delay.tv_usec;
	if (elem->expires.tv_usec >= 1000000) {
		elem->expires.tv_sec++;
		elem->expires.tv_usec -= 1000000;
	}

	if (entry == data->queue_head && entry->tail - 1 == entry->head)
		nettest_schedule(data, elem);

	return elem;
}

static void
nettest_timeout(evutil_socket_t fd, short what, void *arg)
{
	struct nettest_data *data = arg;
	struct timespec now;

	clock_gettime(CLOCK_BOOTTIME, &now);
	now.tv_nsec /= 1000;

	while (data->queue_head) {
		struct nettest_entry *entry;
		struct nettest_elem *elem;

		entry = data->queue_head;
		if (entry->head == 256) {
			/* Reached end of this queue entry, go to next */
			data->queue_head = entry->next;
			entry->head = 0;

			/* Add this entry to the free list */
			entry->next = queue_free;
			queue_free = entry;
			if (!data->queue_head) {
				/* That was the last entry, empty queue */
				data->queue_tail = NULL;
				break;
			}
			entry = data->queue_head;
		}

		if (entry->head == entry->tail)
			/* No more elements in this queue entry (and queue) */
			break;

		elem = entry->elems + entry->head;

		if (now.tv_sec > elem->expires.tv_sec ||
		    (now.tv_sec == elem->expires.tv_sec &&
		     now.tv_nsec >= elem->expires.tv_usec)) {
			nettest_schedule(data, elem);
		    	break;
		}

		entry->head++;

		switch (elem->action) {
		case NETTEST_INPUT:
			data->orig_input(elem->p, elem->netif);
			break;
		#if LWIP_IPV4
		case NETTEST_OUTPUT:
			break;
			data->orig_output(elem->netif, elem->p, ip_2_ip4(&elem->addr));
		#endif
		#if LWIP_IPV6
		case NETTEST_OUTPUT_IP6:
			data->orig_output_ip6(elem->netif, elem->p, ip_2_ip6(&elem->addr));
			break;
		#endif
		case NETTEST_LINKOUTPUT:
			data->orig_linkoutput(elem->netif, elem->p);
			break;
		default:
			pbuf_free(elem->p);
			break;
		}
	}
}

static err_t
nettest_input(struct pbuf *p, struct netif *inp)
{
	struct nettest_data *data = nettest_data + inp->num;
	if (!data->drop_all && rand_r(&data->seed) >= data->drop) {
		struct nettest_elem *elem = nettest_enqueue(data, p, inp);
	 	elem->action = NETTEST_INPUT;
	} else
		pbuf_free(p);
	return ERR_OK;
}

#if LWIP_IPV4
static err_t
nettest_output(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)
{
	struct nettest_data *data = nettest_data + netif->num;
	if (!data->drop_all && rand_r(&data->seed) >= data->drop) {
		struct nettest_elem *elem = nettest_enqueue(data, p, netif);
		elem->action = NETTEST_OUTPUT;
		ip_addr_copy_from_ip4(elem->addr, *ipaddr);
	} else
		pbuf_free(p);
	return ERR_OK;
}
#endif /* LWIP_IPV4*/

#if LWIP_IPV6
static err_t
nettest_output_ip6(struct netif *netif, struct pbuf *p, const ip6_addr_t *ipaddr)
{
	struct nettest_data *data = nettest_data + netif->num;
	if (!data->drop_all && rand_r(&data->seed) >= data->drop) {
		struct nettest_elem *elem = nettest_enqueue(data, p, netif);
		elem->action = NETTEST_OUTPUT_IP6;
		ip_addr_copy_from_ip6(elem->addr, *ipaddr);
	} else
		pbuf_free(p);
	return ERR_OK;
}
#endif /* LWIP_IPV6 */

static err_t
nettest_linkoutput(struct netif *netif, struct pbuf *p)
{
	struct nettest_data *data = nettest_data + netif->num;
	if (!data->drop_all && rand_r(&data->seed) >= data->drop) {
		struct nettest_elem *elem = nettest_enqueue(data, p, netif);
		elem->action = NETTEST_LINKOUTPUT;		
	} else
		pbuf_free(p);
	return ERR_OK;
}

int
nettest_add(struct event_base *base, struct netif *netif, unsigned int delay_us, float drop_rate)
{
	struct nettest_data *data = nettest_data + netif->num;
	int ether;

	if (data->ev)
		return -1;

	data->ev = evtimer_new(base, nettest_timeout, data);
	data->seed = (unsigned int) time(0);
	data->delay.tv_sec = delay_us / 1000000;
	data->delay.tv_usec = delay_us - data->delay.tv_sec * 1000000;
	if (drop_rate > 1.0)
		drop_rate = 1.0;
	else if (!(drop_rate > 0.0))
		drop_rate = 0.0;
	data->drop_all = drop_rate == 1.0;
	data->drop = (UINT_MAX + 1ULL) * (double) drop_rate;

	ether = netif->flags & (NETIF_FLAG_ETHERNET | NETIF_FLAG_ETHARP);

	if (netif->input) {
		data->orig_input = netif->input;
		netif->input = nettest_input;
	}
#if LWIP_IPV4
	if (!ether && netif->output) {
		data->orig_output = netif->output;
		netif->output = nettest_output;
	}
#endif /* LWIP_IPV4*/
#if LWIP_IPV6
	if (!ether && netif->output_ip6) {
		data->orig_output_ip6 = netif->output_ip6;
		netif->output_ip6 = nettest_output_ip6;
	}
#endif /* LWIP_IPV6 */
	if (ether && netif->linkoutput) {
		data->orig_linkoutput = netif->linkoutput;
		netif->linkoutput = nettest_linkoutput;
	}

	return 0;
}

void
nettest_remove(struct netif *netif)
{
	struct nettest_data *data = nettest_data + netif->num;
	struct nettest_entry *entry;

	if (!data->ev)
		return;

	for (entry = data->queue_head; entry; entry = entry->next) {
		struct nettest_elem *elem;
		int i;
		for (i = entry->head; i < entry->tail; i++) {
			elem = entry->elems + i;
			pbuf_free(elem->p);
		}
	}

	if (data->queue_tail) {
		data->queue_tail->next = queue_free;
		queue_free = data->queue_tail;
	}

	evtimer_del(data->ev);

	netif->input = data->orig_input;
#if LWIP_IPV4
	netif->output = data->orig_output;
#endif /* LWIP_IPV4*/
#if LWIP_IPV6
	netif->output_ip6 = data->orig_output_ip6;
#endif /* LWIP_IPV6 */
	netif->linkoutput = data->orig_linkoutput;

	memset(data, 0, sizeof(*data));
}
