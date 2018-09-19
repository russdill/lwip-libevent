#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <sys/time.h>

#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/stats.h>
#include <lwip/ip4.h>
#include <lwip/init.h>
#include <lwip/priv/tcp_priv.h>
#include <lwip/dns.h>
#include <lwip/snmp.h>
#include <lwip/etharp.h>
#include <netif/ethernet.h>

#include <event2/event.h>

#include "netif/processif.h"
#include "netif/fdf.h"

struct netif *
processif_add(struct event_base *base, const char *script, int ether)
{
	struct processif_data *data;

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds))
		return NULL;

	pid = fork();
	if (pid < 0)
		return NULL;

	if (pid == 0) {
		close(0);
		close(1);
		close(fds[0]);
		if (fds[1] != 0)
			dup2(fds[1], 0);
		if (fds[1] != 1)
			dup2(fds[1], 1);
		if (fds[1] != 0 && fds[1] != 1)
			close(fds[1]);
		execl("/bin/sh", "/bin/sh" "-c", script, NULL);
		exit(127);
	}

	close(fds[1]);
	return fdif(base, fds[0], fds[0], ether);
}
