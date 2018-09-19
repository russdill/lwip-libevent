#ifndef __PBUF_IOVEC_H__
#define __PBUF_IOVEC_H__

#include <lwip/arch.h>

struct pbuf;
struct iovec;

int pbuf_writev(int fd, const struct pbuf *p, struct iovec *iov, u16_t n);
int pbuf_readv(int fd, struct pbuf *p, struct pbuf **last, struct iovec *iov, u16_t n);


#endif
