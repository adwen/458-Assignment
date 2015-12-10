#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_nat.h"
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

void processIP(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *interface){

    /* Sanity Check: Length of Ethernet Header */
    if (len < ethernetHeaderSize + ipHeaderSize) {
        printf("Ethernet Header invalid length... Terminating.\n");
        return;
    }

    /* Sanity Check: Length of IP Header */
    sr_ip_hdr_t *ipHeader = (sr_ip_hdr_t *) (packet + ethernetHeaderSize);
    if (len < ethernetHeaderSize + (ipHeader->ip_hl * 4)) {
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

    /* If the NAT is enabled, handle it in NAP Function */
    // TODO: TCP ISNT IMPLMENETED
    if (sr->natFlag) {
        processNatIP(sr, packet, len, interface);
        return;
    }

    // Check if destination interface is for us
    struct sr_if *destination = getIpInterface(sr, ipHeader->ip_dst);

	// If the destination is not for us, we forward!
    if (!destination) {
        ipForwarding(sr, packet, len);
    }

	// If destination is for us, we handle it accordingly
	else {

        // TCP or UDP => destination unreachable ICMP
        if (ipHeader->ip_p == UDP || ipHeader->ip_p == TCP) {
            sendICMP(sr, packet, len, DESTINATION_UNREACHABLE, PORT_UNREACHABLE_CODE);
        }

        if (ipHeader->ip_p == ICMP) {
            processICMP(sr, packet, len);
        }

    }
}


void ipForwarding(struct sr_instance *sr, uint8_t *packet, unsigned int len){


    // Construct IP Header
    sr_ip_hdr_t *ipHeader = (sr_ip_hdr_t *)(packet + ethernetHeaderSize);

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


// New NAT handling function
void processNatIP(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *interface){

    sr_ip_hdr_t *ipHeader = (sr_ip_hdr_t *) (packet + ethernetHeaderSize);

    uint8_t protocolType = ipHeader->ip_p;


    if (protocolType == TCP){
        // Create the tcp header and print it
        //TODO:sr_tcp_hdr_t *tcpHeader = (sr_tcp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + (ipHeader->ip_hl * 4));

        //TODO: Need to Update the port and Update the checksum
    }

    if (protocolType == ICMP){
        // If the interface name matches the internal nat interface
        if (!strncmp(interface->name, internalNat, sr_IFACE_NAMELEN)) {
            /* received from internal interface */

            // Check if this this router is the destination
            struct sr_if *destination = getIpInterface(sr, ipHeader->ip_dst);

            // If the destination is not for us, handle it with ICMP
            if (destination != NULL) {
                processICMP(sr, packet, len);
            }

            // Otherwise, if the destination is not for us, need to forward it
            else {
                /* outbound */

                // Construct Type 0 ICMP Header
                sr_icmp_t0_hdr_t *icmpHeader = (sr_icmp_t0_hdr_t *) (packet + ethernetHeaderSize + (ipHeader->ip_hl * 4));

                // Look up the mapping associated with given internal ip port pair
                struct sr_nat_mapping *natMapping = sr_nat_lookup_internal(&(sr->nat), ipHeader->ip_src, icmpHeader->icmp_id, nat_mapping_icmp);

                // No such nat mapping => insert into the mapping list
                if (!natMapping) {
                    natMapping = sr_nat_insert_mapping(&(sr->nat), ipHeader->ip_src, icmpHeader->icmp_id, nat_mapping_icmp);
                }

                // Get external Nat Interface
                struct sr_if *externalNatInterface = sr_get_interface(sr, externalNat);

                /* Update the ICMP and IP Header */
                ipHeader->ip_src = externalNatInterface->ip;
                ipHeader->ip_sum = 0;
                ipHeader->ip_sum = cksum(ipHeader, ipHeader->ip_hl * 4);
                icmpHeader->icmp_id = natMapping->aux_ext;
                icmpHeader->icmp_sum = 0;
                icmpHeader->icmp_sum = cksum(icmpHeader, ntohs(ipHeader->ip_len) - (ipHeader->ip_hl * 4));

                free(natMapping);

                // Forward th IP
                ipForwarding(sr, packet, len);
            }
        }

        // Otherwise: if the interface name does match external nat interface
        else if (!strncmp(interface->name, externalNat, sr_IFACE_NAMELEN)) {
            /* received from external interface */

            // Check the destination
            struct sr_if *destination = getIpInterface(sr, ipHeader->ip_dst);

            // If the destination isn't for us, just drop it
            if (destination == NULL) {
                return;
            }

            // If the destination is for us: Same behaviour
            else {
                /* inbound */

                sr_icmp_t0_hdr_t *icmpHeader = (sr_icmp_t0_hdr_t *)(packet + ethernetHeaderSize + (ipHeader->ip_hl * 4));

                struct sr_nat_mapping *natMapping = sr_nat_lookup_external(&(sr->nat), icmpHeader->icmp_id, nat_mapping_icmp);

                if (!natMapping) {
                    return;
                }

                /* Update the ICMP and IP Header */
                ipHeader->ip_dst = natMapping->ip_int;
                ipHeader->ip_sum = 0;
                ipHeader->ip_sum = cksum(ipHeader, ipHeader->ip_hl * 4);
                icmpHeader->icmp_id = natMapping->aux_int;
                icmpHeader->icmp_sum = 0;
                icmpHeader->icmp_sum = cksum(icmpHeader, ntohs(ipHeader->ip_len) - (ipHeader->ip_hl * 4));

                free(natMapping);

                ipForwarding(sr, packet, len);
            }
        }
    }
}
