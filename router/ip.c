#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "icmp.h"
#include "ip.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_router.h"
#define DEBUG 1

void processIP(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface){
    //assert(sr);
    //assert(packet);
    //assert(iface);

    /* Sanity Check: Length of Ethernet Header */
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
        printf("Ethernet Header invalid length... Terminating.\n");
        return;
    }

    /* Sanity Check: Length of IP Header */
    sr_ip_hdr_t *ipHeader = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    if (len < sizeof(sr_ethernet_hdr_t) + (ipHeader->ip_hl * 4)) {
        printf("IP Header invalid length... Terminating.\n");
        return;
    }

    /* Sanity Check: Checksums */
    uint16_t currentChecksum = ipHeader->ip_sum;
    ipHeader->ip_sum = 0;

    uint16_t computedSum = cksum(ipHeader, ipHeader->ip_hl * 4);
    ipHeader->ip_sum = currentChecksum;

    if (currentChecksum != computedSum) {
        fprintf(stderr, "Failed to process IP header, incorrect checksum\n");
        return;
    }

    /*
    if (sr->nat_enabled) {
        sr_nat_handle_ip(sr, packet, len, iface);
        return;
    }
    */

    /* is it for me? */
    struct sr_if *destination = getIpInterface(sr, ipHeader->ip_dst);

	// If the destination is not for us, we forward!
    if (!destination) {
        ipForwarding(sr, packet, len);
    }

	// If destination is for us, we handle it accordingly
	else {
        if (ipHeader->ip_p == ip_protocol_icmp) {
            processICMP(sr, packet, len);
        }

		else if (ipHeader->ip_p == ip_protocol_tcp || ipHeader->ip_p == ip_protocol_udp) {
            sendICMP(sr, packet, len, DESTINATION_UNREACHABLE, PORT_UNREACHABLE_CODE);
        }
    }
}


void ipForwarding(struct sr_instance *sr, uint8_t *packet, unsigned int len){
    //assert(sr);
    //assert(packet);

    // Construct IP Header
    sr_ip_hdr_t *ipHeader = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    /* Forwading Logistics */
    // Decrement TTL
    ipHeader->ip_ttl = ipHeader->ip_ttl - 1;
    // Check if TTL Expried
    if (ipHeader->ip_ttl == 0) {
        sendICMP(sr, packet, len, TIME_EXCEEDED, TTL_CODE);
        return;
    }

    // New Checksum
    ipHeader->ip_sum = 0;       // reset to 0 first
    ipHeader->ip_sum = cksum(ipHeader, ipHeader->ip_hl * 4);

    /// Look for the LPM
    struct sr_rt *matchingEntry = findLPM(sr, ipHeader->ip_dst);

    // No LPM => Send ICMP
    if (matchingEntry == NULL) {
        printf("No LPM Match found... sending ICMP.\n");
        sendICMP(sr, packet, len, DESTINATION_UNREACHABLE, NET_UNREACHABLE_CODE);
        return;
    }

    // Get the outgoing interface to send through
    struct sr_if *sendingInterface = sr_get_interface(sr, matchingEntry->interface);
    sendToInterface(sr, packet, len, sendingInterface, matchingEntry->gw.s_addr);
}
