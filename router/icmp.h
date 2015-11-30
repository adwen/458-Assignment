#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_router.h"

void constructHeaderIP(sr_ip_hdr_t *ipHeader, sr_ip_hdr_t *previous, uint32_t newLength, uint32_t newDestination, struct sr_if *interface, uint8_t icmpType, uint8_t code);
void constructType3(sr_icmp_t3_hdr_t *Type3, uint8_t type, uint8_t code, sr_ip_hdr_t *previous);
void constructHeaderEcho(sr_icmp_hdr_t *icmpHeader, uint32_t newLength, uint8_t type, uint8_t code, sr_ip_hdr_t *previous);
void icmpMessage(struct sr_instance *sr, uint8_t *packet, uint8_t icmp_type, uint8_t icmp_code);
