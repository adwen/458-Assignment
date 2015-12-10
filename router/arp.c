#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_nat.h"
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


void processARP(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *interface){

	/* Sanity Check: Length of Ethernet Header */
    if (len < (ethernetHeaderSize + sizeof(sr_arp_hdr_t))) {
        printf("ARP Header invalid length... Terminating.\n");
        return;
    }

	/* Sanity Check: Check if we received a ethernet packet */
    sr_arp_hdr_t *arpHeader = (sr_arp_hdr_t *)(packet + ethernetHeaderSize);
    if (ntohs(arpHeader->ar_hrd) != ARP_ETHERNET_HEADER) {
		printf("Error: Packet was not a Ethernet Frame... Terminating\n");
        return;
    }

    /* Sanity Check: Check if we received a IP Protocol packet */
    if (ntohs(arpHeader->ar_pro) != IP_PACKET) {
		printf("Error: Packet was not a IP Protocol Packet... Terminating\n");
        return;
    }

    /* Check if the destination is for us or not */
    struct sr_if *destination = getIpInterface(sr, arpHeader->ar_tip);
    if (!destination) {
		printf("Error: ARP Packet was not intended for this router interface... Terminating\n");
        return;
    }

	/* Check the opCode (Type of ARP Packet) */
    unsigned short opCode = ntohs(arpHeader->ar_op);

	// ARP Request Case: simply send a ARP Reply only if target ip is in one of our interfaces
    if (opCode == ARP_REQUEST) {
        arpReply(sr, packet, interface, destination);
    }

	/* ARP Reply Case: Cache entry iff the target IP address is one of our router’s IP addresses. */
	else if (opCode == ARP_REPLY) {

		// Check if found
        struct sr_arpreq *arpEntryPointer = sr_arpcache_insert(&(sr->cache), arpHeader->ar_sha, arpHeader->ar_sip);

		// Case where it is found
        if (arpEntryPointer) {
            struct sr_packet *arpPacket = NULL;
            struct sr_if *sendingInterface = NULL;
            sr_ethernet_hdr_t *ethernetHeader = NULL;

            arpPacket = arpEntryPointer->packets;

			// While we still have a valid ARP Entry, send it out contiously
            while (arpPacket) {

				// Get the sending Interface from the current arpPacket
                sendingInterface = sr_get_interface(sr, arpPacket->iface);

				// Build the ethernet header from the arpPacket's buffer, has destination MAC empty
                ethernetHeader = (sr_ethernet_hdr_t *)(arpPacket->buf);
                memcpy(ethernetHeader->ether_dhost, arpHeader->ar_sha, ETHER_ADDR_LEN);
                memcpy(ethernetHeader->ether_shost, sendingInterface->addr, ETHER_ADDR_LEN);

				// Send out the Packet and traverse to the next ARP entry
                sr_send_packet(sr, arpPacket->buf, arpPacket->len, arpPacket->iface);
                arpPacket = arpPacket->next;
            }
            sr_arpreq_destroy(&(sr->cache), arpEntryPointer);
        }
    }
}



void arpRequest(struct sr_instance *sr, struct sr_if *sendingInterface, uint32_t targetIP){
    assert(sr);
    assert(sendingInterface);

	// Get the sending packet Length
    unsigned int len = ethernetHeaderSize + sizeof(sr_arp_hdr_t);
    uint8_t *newLength = (uint8_t *) malloc(len);
    assert(newLength);

	// Use newlength to construct the sending packet
    sr_ethernet_hdr_t *ethernetHeader = (sr_ethernet_hdr_t *) newLength;
    sr_arp_hdr_t *arpHeader = (sr_arp_hdr_t *) (newLength + ethernetHeaderSize);

    // Copy in Ethernet Header values
    memset(ethernetHeader->ether_dhost, 255, ETHER_ADDR_LEN);
    memcpy(ethernetHeader->ether_shost, sendingInterface->addr, ETHER_ADDR_LEN);
    ethernetHeader->ether_type = htons(ARP_PACKET);

    // Fill in ARP values
    arpHeader->ar_hrd = htons(ARP_ETHERNET_HEADER);
    arpHeader->ar_pro = htons(IP_PACKET);
    arpHeader->ar_hln = ETHER_ADDR_LEN;
    arpHeader->ar_pln = sizeof(uint32_t);
    arpHeader->ar_op = htons(ARP_REQUEST);
    memcpy(arpHeader->ar_sha, sendingInterface->addr, ETHER_ADDR_LEN);
    arpHeader->ar_sip = sendingInterface->ip;
    memset(arpHeader->ar_tha, 0, ETHER_ADDR_LEN);
    arpHeader->ar_tip = targetIP;

	// Send out our new Packet and Free it due to malloc
    sr_send_packet(sr, newLength, len, sendingInterface->name);
    free(newLength);
}



void arpReply(struct sr_instance *sr, uint8_t *packet, struct sr_if *sendingInterface, struct sr_if *senderInterface){
    assert(sr);
    assert(packet);
    assert(sendingInterface);
    assert(senderInterface);

	// Construct Ethernet Header from Packet
    sr_ethernet_hdr_t *ethernetHeader = (sr_ethernet_hdr_t *) packet;

	// Construct ARP Header from packet
    sr_arp_hdr_t *arpHeader = (sr_arp_hdr_t *)(packet + ethernetHeaderSize);

	// Size of both combined = how big our new packet Header should be
    unsigned int len = ethernetHeaderSize + sizeof(sr_arp_hdr_t);
    uint8_t *newLength = (uint8_t *)malloc(len);
    assert(newLength);

	// Create a new Ethernet Header from the newLength we just defined
    sr_ethernet_hdr_t *newEthernet = (sr_ethernet_hdr_t *) newLength;
    sr_arp_hdr_t *newARP = (sr_arp_hdr_t *)(newLength + ethernetHeaderSize);

    // Fill in the new ethernet values
    memcpy(newEthernet->ether_dhost, ethernetHeader->ether_shost, ETHER_ADDR_LEN);
    memcpy(newEthernet->ether_shost, sendingInterface->addr, ETHER_ADDR_LEN);
    newEthernet->ether_type = ethernetHeader->ether_type;

    // Fill in the new ARP values
    newARP->ar_hrd = arpHeader->ar_hrd;
    newARP->ar_pro = arpHeader->ar_pro;
    newARP->ar_hln = arpHeader->ar_hln;
    newARP->ar_pln = arpHeader->ar_pln;
    newARP->ar_op = htons(ARP_REPLY);
    memcpy(newARP->ar_sha, senderInterface->addr, ETHER_ADDR_LEN);
    newARP->ar_sip = senderInterface->ip;
    memcpy(newARP->ar_tha, arpHeader->ar_sha, ETHER_ADDR_LEN);
    newARP->ar_tip = arpHeader->ar_sip;

	// Send the Packet and free it
    sr_send_packet(sr, newLength, len, sendingInterface->name);
    free(newLength);
}
