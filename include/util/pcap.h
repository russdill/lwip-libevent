#ifndef __PCAP_H__
#define __PCAP_H__

struct netif;

int pcap_dump_add(struct netif *netif, const char *pcap_file);
void pcap_dump_remove(struct netif *netif);

#endif