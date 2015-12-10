#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "icmp.h"
#include "ip.h"
#include "arp.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_router.h"
#define DEBUG 1

void processICMP(struct sr_instance *sr, uint8_t *packet, unsigned int len){
    //assert(sr);
    //assert(packet);

    sr_ip_hdr_t *ipHeader = (sr_ip_hdr_t *)(packet + ethernetHeaderSize);

    // Sanity Check: Check the length of the header
    if (len < ethernetHeaderSize + (ipHeader->ip_hl * 4) + sizeof(sr_icmp_hdr_t)) {
        printf("ICMP Header insufficient length... Terminating.\n");
        return;
    }

	// Construct the ICMP Header from the packet
    sr_icmp_hdr_t *icmpHeader = (sr_icmp_hdr_t *) (packet + ethernetHeaderSize + (ipHeader->ip_hl * 4));

    // Sanity Check: Verify the currentChecksum checks out
    uint16_t currentChecksum = icmpHeader->icmp_sum;
    icmpHeader->icmp_sum = 0;
    uint16_t computedChecksum = cksum(icmpHeader, ntohs(ipHeader->ip_len) - (ipHeader->ip_hl * 4));
    icmpHeader->icmp_sum = currentChecksum;
    if (currentChecksum != computedChecksum) {
        printf("ICMP Checksum incorrect... Terminating\n");
        return;
    }

	// If it is a valid ICMP Type, send it accordingly
    if (icmpHeader->icmp_type == ECHO_REQUEST && icmpHeader->icmp_code == ECHO_REQUEST_CODE) {
        sendICMP(sr, packet, len, ECHO_REPLY, ECHO_REPLY_CODE);
    }
}

void sendICMP(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint8_t icmp_type, uint8_t icmp_code){

    sr_ethernet_hdr_t *ethernetHeader = (sr_ethernet_hdr_t *) packet;
    sr_ip_hdr_t *ipHeader = (sr_ip_hdr_t *) (packet + ethernetHeaderSize);
    sr_icmp_hdr_t *icmpHeader = (sr_icmp_hdr_t *) (packet + ethernetHeaderSize + (ipHeader->ip_hl * 4));

    // Get the LPM of the IP source address in our router
    struct sr_rt *routingTableEntry = findLPM(sr, ipHeader->ip_src);

    if (!routingTableEntry) {
        printf("Routing Table entry not found... Terminating.\n");
        return;
    }

    // Get the sending interface
    struct sr_if *sendingInterface = sr_get_interface(sr, routingTableEntry->interface);

	/* Case if ICMP TYPE is a echo reply */
    if (icmp_type == ECHO_REPLY) {

		// Update the Ethernet Header source and destination
		memset(ethernetHeader->ether_shost, 0, ETHER_ADDR_LEN);
        memset(ethernetHeader->ether_dhost, 0, ETHER_ADDR_LEN);

        // Update IP Header fields: for echo reply, dest is original source address and vice versa
        uint32_t newDestination = ipHeader->ip_src;
        ipHeader->ip_src = ipHeader->ip_dst;			// New Source is their original destination
        ipHeader->ip_dst = newDestination;

        // Update ICMP Type: Echo reply
        icmpHeader->icmp_type = ECHO_REPLY;
        icmpHeader->icmp_code = ECHO_REPLY_CODE;

		// Recompute ICMP Checksum
        icmpHeader->icmp_sum = 0;
        icmpHeader->icmp_sum = cksum(icmpHeader, ntohs(ipHeader->ip_len) - (ipHeader->ip_hl * 4));

        // Send the ICMP to the sending interface
        sendToInterface(sr, packet, len, sendingInterface, routingTableEntry->gw.s_addr);
    }

	/* Case if ICMP TYPE is a Unreachable: Type 3 ICMP */
	if (icmp_type == DESTINATION_UNREACHABLE) {

		// Calculate the new length of the packet to be sent (convert to Type 3 ICMP)
		unsigned int newLength = ethernetHeaderSize + ipHeaderSize + type3HeaderSize;
		uint8_t *newPacket = (uint8_t *) malloc(newLength);
		assert(newPacket);

		// Construct the Ethernet, IP, ICMP Type 3 header for the new Packet
		sr_ethernet_hdr_t *newEthernetHeader = (sr_ethernet_hdr_t *) newPacket;
		sr_ip_hdr_t *newIpHeader = (sr_ip_hdr_t *) (newPacket + ethernetHeaderSize);
		sr_icmp_t3_hdr_t *type3Header = (sr_icmp_t3_hdr_t *) (newPacket + ethernetHeaderSize + ipHeaderSize);

		// Set ethernet source / destination and packet Type
		memset(newEthernetHeader->ether_shost, 0, ETHER_ADDR_LEN);
		memset(newEthernetHeader->ether_dhost, 0, ETHER_ADDR_LEN);
		newEthernetHeader->ether_type = htons(IP_PACKET);

		// Fill in IP header fields
		newIpHeader->ip_v = 4;
		newIpHeader->ip_hl = ipHeaderSize / 4;
		newIpHeader->ip_tos = 0;
		newIpHeader->ip_len = htons(ipHeaderSize + type3HeaderSize);
		newIpHeader->ip_id = htons(0);
		newIpHeader->ip_off = htons(IP_DF);
		newIpHeader->ip_ttl = 64;
		newIpHeader->ip_p = ICMP;
		// Check for codes here: Port unreachable goes back to sender
		if (icmp_code == PORT_UNREACHABLE_CODE) {
			newIpHeader->ip_src = ipHeader->ip_dst;
		}
		// Otherwise: forwarding goes to the sending interface
		else {
			newIpHeader->ip_src = sendingInterface->ip;
		}
		newIpHeader->ip_dst = ipHeader->ip_src;

		// Update IP Checksum
		newIpHeader->ip_sum = 0;
		newIpHeader->ip_sum = cksum(newIpHeader, ipHeaderSize);

		// Fill in ICMP Type 3 Header
		type3Header->icmp_type = icmp_type;
		type3Header->icmp_code = icmp_code;
		type3Header->unused = 0;
		type3Header->next_mtu = 0;
		memcpy(type3Header->data, ipHeader, ICMP_DATA_SIZE);	// Cppy the data over

		// Update ICMP Type 3 checksum
		type3Header->icmp_sum = 0;
		type3Header->icmp_sum = cksum(type3Header, type3HeaderSize);

		// Send Type 3 to sending interface
		sendToInterface(sr, newPacket, newLength, sendingInterface, routingTableEntry->gw.s_addr);
		free(newPacket);
	}

	/* Case if ICMP Type is Time exceeded: TYPE 11 ICMP*/
	if (icmp_type == TIME_EXCEEDED) {
		unsigned int newLength = ethernetHeaderSize + ipHeaderSize + type11HeaderSize;
		uint8_t *newPacket = (uint8_t *)malloc(newLength);
		assert(newPacket);

		sr_ethernet_hdr_t *newEthernetHeader = (sr_ethernet_hdr_t *)newPacket;
		sr_ip_hdr_t *newIpHeader = (sr_ip_hdr_t *)(newPacket + ethernetHeaderSize);
		sr_icmp_t11_hdr_t *type11Header = (sr_icmp_t11_hdr_t *)(newPacket + ethernetHeaderSize + ipHeaderSize);

		// Update ethernet destination / host and packet type
		memset(newEthernetHeader->ether_shost, 0, ETHER_ADDR_LEN);
		memset(newEthernetHeader->ether_dhost, 0, ETHER_ADDR_LEN);
		newEthernetHeader->ether_type = htons(IP_PACKET);

		// Update IP header fields
		newIpHeader->ip_v = 4;
		newIpHeader->ip_hl = ipHeaderSize / 4;
		newIpHeader->ip_tos = 0;
		newIpHeader->ip_len = htons(ipHeaderSize + type11HeaderSize);
		newIpHeader->ip_id = htons(0);
		newIpHeader->ip_off = htons(IP_DF);
		newIpHeader->ip_ttl = 64;
		newIpHeader->ip_p = ICMP;
		newIpHeader->ip_src = sendingInterface->ip;
		newIpHeader->ip_dst = ipHeader->ip_src;

		// Update the checksum
		newIpHeader->ip_sum = 0;
		newIpHeader->ip_sum = cksum(newIpHeader, ipHeaderSize);

		// Update ICMP header
		type11Header->icmp_type = icmp_type;
		type11Header->icmp_code = icmp_code;
		type11Header->unused = 0;
		// Copy data from into the ICMP header
		memcpy(type11Header->data, ipHeader, ICMP_DATA_SIZE);

		// Update ICMP type 11 checksum
		type11Header->icmp_sum = 0;
		type11Header->icmp_sum = cksum(type11Header, type11HeaderSize);

		sendToInterface(sr, newPacket, newLength, sendingInterface, routingTableEntry->gw.s_addr);
		free(newPacket);
	}
}
