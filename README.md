# libevent support for lwIP

This contains a number of components for use of lwIP with libevent on Linux.
It includes a core for integrating lwIP into the libevent loop, a set of
netifs that utilize libevent, and accessory utilities.

## Core Library

The core library, (libevent.c and include/util/libevent.h), incorporates lwIP
timeouts into the libevent loop. It should be used with NO_SYS_NO_TIMERS and
NO_SYS. libevent_timeouts_init should be called at startup.
sys_timer_add_internal can be used to add additional lwIP style timeouts.

## Utility Code

### pcap

The pcap utility code allows all packets received on and transmitted via a
specified netif to be stored to a pcap capture file.

### nettest

Induces latency and dropped packets for a specified netif. This can be used
for testing. The latency value is fixed and given in microseconds. The
packet drop rate is used to randomly select packets to be dropped and ranges
between 0.0 (disabled) and 1.0 (all packets).

### sockaddr

Allows easy conversion between lwIP address structures and Linux sockaddr
structures.

### pbuf_iovec

Allows reading to/from pbufs using iovecs. This allows for scatter/gather IO
using readv/writev. This is most useful for writev.

### host

This is not Linux or libevent specific, but provides additional host lookup
services around dns_gethostbyname. It provides a lookup engine that supports
domain names. Search domains can be added via host_add_search. When host
names are looked up, the tail of the search domains will be added in turn along
with the bare lookup.

### lwipevbuf

Links an lwIP TCP connection to a pair of libevent evbuffers. Ideally an lwIP
TCP connection could provide a backing to a bufferevent, but that would
currently require patching libevent as that interface is not exported. Addding
to the write queues data to be written and new data appears in the read buffer.
A readcb, writecb, and eventcb is provided just as in bufferevent.

### lwipevbuf_bev_join

Joins an lwipevbuf and a bufferevent into a pipe, passing all data between them.

## netifs

### fdif

Connects a pair (or single) of file descriptors to a netif. Reads are expected
to occur as datagrams. Datagrams that are read are injected as received packets
and transmitted packets are written to the output file descriptor.

The netif can be configured for Ethernet datagrams or for IP datagrams.

### processif

A simple adaptation of fdif that starts a process with a pair of file
descriptors that are then passed to fdif. All process stdout is injected to the
netif and all netif output is injected to the process's stdin

### udptapif

Sends and receives netif datagrams via a UDP port. This can open two UDP ports,
one for raw datagrams and one for datagrams prepended with a 2 byte BE length.
The netif keeps track of recent clients and associated hardware addresses.
Broadcast packets are sent to all recent clients, and any addressed packets
are only sent to the appropriate client.

### vdeportif

Uses libvedeplug2 to connect to a VDE swtich.

### vdeswitchif

Emulates a VDE switch allowing libvdeplug2 clients to connect.

### slirpif

Provides a slirp like interface that uses the host's local IP stack to send
and receive packets. Currently supports TCP and UDP. This is primarily for
testing.

