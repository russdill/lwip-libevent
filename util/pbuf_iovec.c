#include <limits.h>
#include <sys/uio.h>
#include <lwip/pbuf.h>

#include "util/pbuf_iovec.h"

int
pbuf_writev(int fd, const struct pbuf *p, struct iovec *iov, u16_t n)
{
	u16_t i;
	for (i = 0; p && i < n; p = p->next, i++) {
		iov[i].iov_base = p->payload;
		iov[i].iov_len = p->len;
	}
	return writev(fd, iov, i);
}

int
pbuf_readv(int fd, struct pbuf *p, struct pbuf **last, struct iovec *iov, u16_t n)
{
	u16_t i;
	int ret;
	struct pbuf *curr;
	for (curr = p, i = 0; curr && i < n; curr = curr->next, i++) {
		iov[i].iov_base = curr->payload;
		iov[i].iov_len = curr->len;
	}
	ret = readv(fd, iov, i);
	if (ret < 0)
		return ret;
	if (ret > USHRT_MAX)
		ret = USHRT_MAX;
	for (curr = p, i = 0; ret && curr && i < n; curr = curr->next, i++) {
		curr->tot_len = ret;
		if (ret < curr->len)
			curr->len = ret;
		else
			ret -= curr->len;
	}
	*last = p->next;
	p->next = NULL;
	return p->tot_len;
}
