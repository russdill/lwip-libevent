#ifndef __HOST_H__
#define __HOST_H__

#include <sys/types.h>
#include <lwip/ip_addr.h>
#include <lwip/err.h>
#include <lwip/opt.h>

#ifndef HOSTS_DEBUG
#define HOSTS_DEBUG LWIP_DBG_OFF
#endif

struct host_data_priv;

struct host_data {
	ip_addr_t ipaddr;
	char fqdn[256];
	void (*found)(struct host_data*);
	void (*failed)(struct host_data*, err_t);
	struct host_data_priv *priv;
};

void host_lookup(struct host_data *data);
void host_abort(struct host_data *data);
static inline int host_busy(struct host_data *data)
{
	return data->priv != NULL;
}

void host_clear_search(void);
void host_add_search(char *search);
const char *host_get_search(unsigned int i);

#endif
