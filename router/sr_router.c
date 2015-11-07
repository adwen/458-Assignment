/**********************************************************************
* file:  sr_router.c
* date:  Mon Feb 18 12:50:42 PST 2002
* Contact: casado@stanford.edu
*
* Description:
*
* This file contains all the functions that interact directly
* with the routing table, as well as the main entry method
* for routing.
*
**********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <arpa/inet.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
        /* REQUIRES */
        assert(sr);

        /* Initialize cache and cache cleanup thread */
        sr_arpcache_init(&(sr->cache));

        pthread_attr_init(&(sr->attr));
        pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
        pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
        pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
        pthread_t thread;

        pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

        /* Add initialization code here! */

}  /* -- sr_init -- */

/* Logic to send an ICMP Type 0 Message */
int ICMP_Message0(
                 struct sr_instance* sr,
                 uint8_t *packet,
                 char* interface,
                 uint8_t code)
{
        printf("Sending ICMP!\n");

        /* Variables */
        size_t ethernetHeaderSize = sizeof(sr_ethernet_hdr_t);
        size_t ipHeaderSize = sizeof(sr_ip_hdr_t);
        size_t icmpHeaderSize = 0;
        struct sr_if *thisInterface = sr_get_interface(sr, interface);

        /* Get the IP and Ethernet headers passed in from the packet */
        sr_ethernet_hdr_t *incomingEthernet = (sr_ethernet_hdr_t *) packet;
        sr_ip_hdr_t *incomingIP = (sr_ip_hdr_t *) (packet + ethernetHeaderSize );
        sr_icmp_t0_hdr_t *incomingICMP = (sr_icmp_t0_hdr_t *) (packet + ethernetHeaderSize + ipHeaderSize);

        icmpHeaderSize = ntohs(incomingIP->ip_len) - incomingIP->ip_hl*4;
        size_t icmpLength = ethernetHeaderSize + ipHeaderSize + icmpHeaderSize;
        uint8_t *icmpPacket = (uint8_t *) malloc(icmpLength);
        bzero(icmpPacket, icmpLength);

        /* Construct the Ethernet Header from the packet */
        sr_ethernet_hdr_t *ethernetHeader = (sr_ethernet_hdr_t *) icmpPacket;
        memcpy(ethernetHeader->ether_dhost, incomingEthernet->ether_shost, ETHER_ADDR_LEN);
        memcpy(ethernetHeader->ether_shost, incomingEthernet->ether_dhost, ETHER_ADDR_LEN);
        ethernetHeader->ether_type = htons(ethertype_ip);

        /* Construct the IP Header from the packet */
        sr_ip_hdr_t *ipHeader = (sr_ip_hdr_t *) (icmpPacket + ethernetHeaderSize);
        ipHeader->ip_v = 4;
        ipHeader->ip_hl = 5;
        ipHeader->ip_tos = 0;
        ipHeader->ip_len = htons(icmpHeaderSize + 20);
        ipHeader->ip_id = 0;
        ipHeader->ip_off = htons(IP_DF);
        ipHeader->ip_ttl = INIT_TTL;
        ipHeader->ip_p = ip_protocol_icmp;
        ipHeader->ip_src = thisInterface->ip;
        ipHeader->ip_dst = incomingIP->ip_src;
        ipHeader->ip_sum = cksum(icmpPacket + ethernetHeaderSize, ipHeader->ip_hl*4);

        /* Construct the ICMP header from the packet */
        sr_icmp_t0_hdr_t *icmpType0 = (sr_icmp_t0_hdr_t *) (icmpPacket + ethernetHeaderSize + ipHeaderSize);
        icmpType0->icmp_code = code;
        icmpType0->icmp_type = 0;
        icmpType0->icmp_identifier = incomingICMP->icmp_identifier;
        icmpType0->icmp_seqnum = incomingICMP->icmp_seqnum;
        icmpType0->icmp_timestamp = incomingICMP->icmp_timestamp;
        memcpy(icmpType0->data, incomingICMP->data, icmpHeaderSize - 10);
        icmpType0->icmp_sum = cksum(icmpPacket + ethernetHeaderSize + ipHeaderSize, icmpHeaderSize);

        printf("Sending ICMP Type 0\n");

        /* Send it out */
        int retval = sr_send_packet(sr, icmpPacket, icmpLength, interface);
        free(icmpPacket);
        return retval;
}

/* Logic to send an ICMP Type 3Message */
int ICMP_Message3(
                 struct sr_instance* sr,
                 uint8_t *packet,
                 char* interface,
                 uint8_t code)
{
        printf("Sending ICMP!\n");

        /* Variables */
        size_t ethernetHeaderSize = sizeof(sr_ethernet_hdr_t);
        size_t ipHeaderSize = sizeof(sr_ip_hdr_t);
        size_t icmpHeaderSize = sizeof(sr_icmp_t3_hdr_t);
        struct sr_if *thisInterface = sr_get_interface(sr, interface);

        /* Get the IP and Ethernet headers passed in from the packet */
        sr_ethernet_hdr_t *incomingEthernet = (sr_ethernet_hdr_t *) packet;
        sr_ip_hdr_t *incomingIP = (sr_ip_hdr_t *) (packet + ethernetHeaderSize );

        size_t icmpLength = ethernetHeaderSize + ipHeaderSize + icmpHeaderSize;
        uint8_t *icmpPacket = (uint8_t *) malloc(icmpLength);
        bzero(icmpPacket, icmpLength);

        /* Construct the Ethernet Header from the packet */
        sr_ethernet_hdr_t *ethernetHeader = (sr_ethernet_hdr_t *) icmpPacket;
        memcpy(ethernetHeader->ether_dhost, incomingEthernet->ether_shost, ETHER_ADDR_LEN);
        memcpy(ethernetHeader->ether_shost, incomingEthernet->ether_dhost, ETHER_ADDR_LEN);
        ethernetHeader->ether_type = htons(ethertype_ip);

        /* Construct the IP Header from the packet */
        sr_ip_hdr_t *ipHeader = (sr_ip_hdr_t *) (icmpPacket + ethernetHeaderSize);
        ipHeader->ip_v = 4;
        ipHeader->ip_hl = 5;
        ipHeader->ip_tos = 0;
        ipHeader->ip_len = htons(icmpHeaderSize + 20);
        ipHeader->ip_id = 0;
        ipHeader->ip_off = htons(IP_DF);
        ipHeader->ip_ttl = INIT_TTL;
        ipHeader->ip_p = ip_protocol_icmp;
        ipHeader->ip_src = thisInterface->ip;
        ipHeader->ip_dst = incomingIP->ip_src;
        ipHeader->ip_sum = cksum(icmpPacket + ethernetHeaderSize, ipHeader->ip_hl*4);


        /* Construct the ICMP header from the packet */
        sr_icmp_t3_hdr_t *icmpType3 = (sr_icmp_t3_hdr_t *) (icmpPacket + ethernetHeaderSize + ipHeaderSize);
        icmpType3->icmp_code = code;
        icmpType3->icmp_type = 3;
        memcpy(icmpType3->data, packet + ethernetHeaderSize, (ipHeader->ip_hl*4) + 8);
        icmpType3->icmp_sum = cksum(icmpPacket + ethernetHeaderSize + ipHeaderSize, icmpHeaderSize);


        printf("Sending ICMP Type 3\n");

        /* Send it out */
        int retval = sr_send_packet(sr, icmpPacket, icmpLength, interface);
        free(icmpPacket);
        return retval;
}

/* Logic to send an ICMP Type 11 Message */
int ICMP_Message11(
                 struct sr_instance* sr,
                 uint8_t *packet,
                 char* interface,
                 uint8_t code)
{
        printf("Sending ICMP!\n");

        /* Variables */
        size_t ethernetHeaderSize = sizeof(sr_ethernet_hdr_t);
        size_t ipHeaderSize = sizeof(sr_ip_hdr_t);
        size_t icmpHeaderSize = sizeof(sr_icmp_t11_hdr_t);
        struct sr_if *thisInterface = sr_get_interface(sr, interface);

        /* Get the IP and Ethernet headers passed in from the packet */
        sr_ethernet_hdr_t *incomingEthernet = (sr_ethernet_hdr_t *) packet;
        sr_ip_hdr_t *incomingIP = (sr_ip_hdr_t *) (packet + ethernetHeaderSize );

        /* Calculate Length of ICMP Header Size */
        size_t icmpLength = ethernetHeaderSize + ipHeaderSize + icmpHeaderSize;
        uint8_t *icmpPacket = (uint8_t *) malloc(icmpLength);
        bzero(icmpPacket, icmpLength);

        /* Construct the Ethernet Header from the packet */
        sr_ethernet_hdr_t *ethernetHeader = (sr_ethernet_hdr_t *) icmpPacket;
        memcpy(ethernetHeader->ether_dhost, incomingEthernet->ether_shost, ETHER_ADDR_LEN);
        memcpy(ethernetHeader->ether_shost, incomingEthernet->ether_dhost, ETHER_ADDR_LEN);
        ethernetHeader->ether_type = htons(ethertype_ip);

        /* Construct the IP Header from the packet */
        sr_ip_hdr_t *ipHeader = (sr_ip_hdr_t *) (icmpPacket + ethernetHeaderSize);
        ipHeader->ip_v = 4;
        ipHeader->ip_hl = 5;
        ipHeader->ip_tos = 0;
        ipHeader->ip_len = htons(icmpHeaderSize + 20);
        ipHeader->ip_id = 0;
        ipHeader->ip_off = htons(IP_DF);
        ipHeader->ip_ttl = INIT_TTL;
        ipHeader->ip_p = ip_protocol_icmp;
        ipHeader->ip_src = thisInterface->ip;
        ipHeader->ip_dst = incomingIP->ip_src;
        ipHeader->ip_sum = cksum(icmpPacket + ethernetHeaderSize, ipHeader->ip_hl*4);


        /* Construct the ICMP header from the packet */
        sr_icmp_t11_hdr_t *icmpType11 = (sr_icmp_t11_hdr_t *) (icmpPacket + ethernetHeaderSize + ipHeaderSize);
        icmpType11->icmp_code = code;
        icmpType11->icmp_type = 11;
        memcpy(icmpType11->data, packet + ethernetHeaderSize, ipHeader->ip_hl*4 + 8);
        icmpType11->icmp_sum = cksum(icmpPacket + ethernetHeaderSize + ipHeaderSize, icmpHeaderSize);

        printf("Sending ICMP Type 11\n");

        /* Send it out */
        int retval = sr_send_packet(sr, icmpPacket, icmpLength, interface);
        free(icmpPacket);
        return retval;
}

/* Logic to send an ARP Message */
int ARP_Message(
        struct sr_instance* sr,
        unsigned short opCode,
        uint32_t targetIP,
        unsigned char targetHardwareAddress[ETHER_ADDR_LEN])
{
        /* Variables */
        size_t ethernetHeaderSize = sizeof(sr_ethernet_hdr_t);
        size_t arpHeaderSize = sizeof(sr_arp_hdr_t);

        /* initialize the ARP Message packet */
        uint8_t *arpPacket = (uint8_t *)malloc(ethernetHeaderSize + arpHeaderSize);
        bzero(arpPacket, ethernetHeaderSize + arpHeaderSize);

        /* Get the interfaces */
        char *interface = get_charpointer_interface(sr, targetIP);
        struct sr_if *sendingInterface = sr_get_interface(sr, interface);

        /* Create the ethernet frame header from the arpPacket */
        sr_ethernet_hdr_t *ethernetHeader = (sr_ethernet_hdr_t *) arpPacket;
        /* If ARP reply */
        if (opCode == arp_op_reply) {
                memcpy(ethernetHeader->ether_dhost, targetHardwareAddress, ETHER_ADDR_LEN);
        }
        /* If ARP Request */
        if (opCode == arp_op_request) {
                memset(ethernetHeader->ether_dhost, 0xff, ETHER_ADDR_LEN);
        }
        else{
            fprintf(stderr, "Error: Somehow got a unidentifiable opcode!\n");
        }
        memcpy(ethernetHeader->ether_shost, sendingInterface->addr, ETHER_ADDR_LEN);
        ethernetHeader->ether_type = htons(ethertype_arp);

        /* Construct the arp header from the arpPacket */
        sr_arp_hdr_t *arpHeader = (sr_arp_hdr_t *) (arpPacket + ethernetHeaderSize);
        arpHeader->ar_hrd = htons(arp_hrd_ethernet);
        arpHeader->ar_pro = htons(ethertype_ip);
        arpHeader->ar_hln = ETHER_ADDR_LEN;
        arpHeader->ar_pln = 4;
        arpHeader->ar_op = htons(opCode);
        memcpy(arpHeader->ar_sha, sendingInterface->addr, ETHER_ADDR_LEN);
        arpHeader->ar_sip = sendingInterface->ip;
        memcpy(arpHeader->ar_tha, targetHardwareAddress, ETHER_ADDR_LEN);
        arpHeader->ar_tip = targetIP;

        /* Send out arp packet */
        printf("Sending Out ARP Packet!\n");
        int retval = sr_send_packet(sr, arpPacket, ethernetHeaderSize + arpHeaderSize, interface);
        free(arpPacket);
        return retval;
}


/* Logic to handle a Incoming ARP Packet */
int process_ARP(struct sr_instance* sr, uint8_t *packet, unsigned int len, char* interface) {

        /* Variables */
        size_t ethernetHeaderSize = sizeof(sr_ethernet_hdr_t);
        size_t arpHeaderSize = sizeof(sr_arp_hdr_t);


        /* Sanity Check */
        if (len < ethernetHeaderSize + arpHeaderSize) {
                fprintf(stderr, "Invalid ARP header size");
                return -1;
        }

        /* Construct the ARP Header from the packet and get it's interface */
        sr_arp_hdr_t *arpHeader = (sr_arp_hdr_t *)(packet + ethernetHeaderSize);
        struct sr_if *thisInterface = sr_get_ip_interface(sr, arpHeader->ar_tip);

        /* Handle a ARP Reply */
        if (arpHeader->ar_op == htons(arp_op_reply)) {
                /* Only cache if the target IP is one of our router's interfaces' IP address */
                printf("Receive ARP reply at interface %s\n", interface);
                struct sr_arpreq *arpRequest = NULL;

                /* Target is for someone else => Only cache if destination in in our interfaces IP addresses */
                if (thisInterface == NULL) {
                        arpRequest = sr->cache.requests;
                        while (arpRequest != NULL) {
                                if (arpRequest->ip != arpHeader->ar_sip) {
                                        arpRequest = arpRequest->next;
                                }
                        }

                        if (arpRequest == NULL) {
                                printf("We coudn't find a match... terminating...\n");
                                return -1;
                        }
                }

                /* Target is Us => Just cache it */
                else if (thisInterface != NULL) {
                        arpRequest = sr_arpcache_insert(&(sr->cache), arpHeader->ar_sha, arpHeader->ar_sip);
                }

                /* Broadcast to all waiting on this ARP request*/
                struct sr_packet *arpPackets = arpRequest->packets;
                while (arpPackets) {

                        /* Get the interface to send to */
                        struct sr_if *sendingInterface = sr_get_interface(sr, interface);

                        /* Construct Ethernet Header from Packet */
                        sr_ethernet_hdr_t *ethernetHeader = (sr_ethernet_hdr_t *) arpPackets->buf;
                        memcpy(ethernetHeader->ether_dhost, arpHeader->ar_sha, ETHER_ADDR_LEN);
                        memcpy(ethernetHeader->ether_shost, sendingInterface->addr, ETHER_ADDR_LEN);

                        /* Construct IP Header with Updated IP TTL and CKsum */
                        sr_ip_hdr_t *ipHeader = (sr_ip_hdr_t *) (arpPackets->buf + ethernetHeaderSize);
                        ipHeader->ip_ttl = (ipHeader->ip_ttl) - 1;
                        ipHeader->ip_sum = 0;
                        ipHeader->ip_sum = cksum(ipHeader, ipHeader->ip_hl*4);
                        sr_send_packet(sr, arpPackets->buf, arpPackets->len, interface);
                        arpPackets = arpPackets->next;
                }

                sr_arpreq_destroy(&(sr->cache), arpRequest);
        }

        /* Handle a ARP Request */
        if (arpHeader->ar_op == htons(arp_op_request)) {

                /* Not for us => Terminate */
                if (thisInterface == NULL) {
                        printf("ARP request is for someone else\n");
                        return -1;
                }

                /* Target is us => Send a ARP Reply */
                else if (thisInterface != NULL) {
                        Debug("ARP request for our router. send ARP Message (Reply)\n");
                        return ARP_Message(sr, arp_op_reply, arpHeader->ar_sip, arpHeader->ar_sha);
                }
        }

        return 0;
}


/* Logic to Process an incoming IP Packet */
int process_IP(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {

        /* Variables */
        size_t ethernetHeaderSize = sizeof(sr_ethernet_hdr_t);
        size_t ipHeaderSize = sizeof(sr_ip_hdr_t);

        /* Sanity Check */
        if (len < ethernetHeaderSize + ipHeaderSize) {
                fprintf(stderr, "Invalid IP header size");
                return -1;
        }

        /* Construct the IP and Ethernet Headers + Get the intended interface */
        sr_ethernet_hdr_t *ethernetHeader = (sr_ethernet_hdr_t *) packet;
        sr_ip_hdr_t *ipHeader = (sr_ip_hdr_t *) (packet + ethernetHeaderSize);
        /* Get intended Interface for this IP Packet */
        struct sr_if *thisInterface = sr_get_ip_interface(sr, ipHeader->ip_dst);

        /* Sanity Check #2*/
        if(!cksum(ipHeader, ipHeader->ip_hl)) {
                fprintf(stderr, "Invalid IP header checksum");
                return -1;
        }


        /* Target is for somewhere else */
        if (thisInterface == NULL) {

                printf("Packet needs to be routed elsewhere\n");

                /* Sanity Check: Make sure the TTL can go on */
                uint8_t currentTTL = ipHeader->ip_ttl;
                if( currentTTL == 1 || currentTTL < 1 ) {
                        printf("TTL Expired: Sending ICMP Type 11\n");
                        return ICMP_Message11(sr, packet, interface, 0);
                }

                /* Find where it should go via routing table from our interface sr */
                struct sr_rt *routingEntryPointer = sr->routing_table;
                while(routingEntryPointer != NULL) {

                        /* Destination address of every entry = logical AND of destination and routing entry mask */
                        uint32_t destinationAddress = ipHeader->ip_dst & routingEntryPointer->mask.s_addr;

                        /* If a Match is found via Longest Prefix Match */
                        if (destinationAddress == routingEntryPointer->dest.s_addr) {
                                printf("Routing Match Found!\n");

                                /* Get the interface for that match and set it as the ethernet shost*/
                                struct sr_if *sendingInterface = sr_get_interface(sr,
                                                                                  routingEntryPointer->interface);
                                memcpy(ethernetHeader->ether_shost, sendingInterface->addr, ETHER_ADDR_LEN);

                                /* Check ARP Cache for next hop MAC address for next hop IP (Longest PRefix) */
                                struct sr_arpentry *cacheEntry = sr_arpcache_lookup(&(sr->cache),
                                                                                    routingEntryPointer->gw.s_addr);

                                /* No longest Prefix Match */
                                if (cacheEntry == NULL) {

                                        printf("Couldn't find LPM in the cache...\n");
                                        struct sr_arpreq *queuereq = sr_arpcache_queuereq(&(sr->cache),
                                                                routingEntryPointer->gw.s_addr, packet, len, interface);
                                        handle_arpreq(sr, queuereq);
                                        return 0;
                                }

                                /* Found Longest Preix Match */
                                else if (cacheEntry != NULL) {

                                        printf("Found LPM!\n");
                                        /* Get the Mac Address from cache match*/
                                        unsigned char *macAddress = cacheEntry->mac;

                                        /* Copy the macaddress into the etherent dhost */
                                        memcpy(ethernetHeader->ether_dhost, macAddress, ETHER_ADDR_LEN);
                                        free(cacheEntry);

                                        /* Update ip Header */
                                        ipHeader->ip_ttl = (ipHeader->ip_ttl) - 1;
                                        ipHeader->ip_sum = 0;
                                        ipHeader->ip_sum = cksum(ipHeader, ipHeader->ip_hl*4);
                                        return sr_send_packet(sr, packet, len, routingEntryPointer->interface);
                                }
                        }
                        routingEntryPointer = routingEntryPointer->next;
                }

                /* Exit while loop => Destination host unreachable */
                printf("Host cannot be reached: Sending ICMP Type 3\n");
                return ICMP_Message3(sr, packet, interface, 1);

        }

        /* Target is us! */
        if (thisInterface != NULL) {
                printf("IP Packet is for here\n");

                /* If it is not a ICMP msg => reply with ICMP Type 3 (Port UNreachable) */
                if (ipHeader->ip_p != ip_protocol_icmp) {
                        Debug("Not ICMP protocol");
                        return ICMP_Message3(sr, packet, interface, 3);  /* port unreachable */
                }

                /* ICMP Msg => we reply only if it is a echo request (Type 8)*/
                else if (ipHeader->ip_p == ip_protocol_icmp) {

                        /* Construct the ICMP header from the packet */
                        sr_icmp_hdr_t *icmpHeader = (sr_icmp_hdr_t *) (packet + ethernetHeaderSize + ipHeaderSize);

                        /* Ignore if it's not an echo request */
                        if (icmpHeader->icmp_type == 3 || icmpHeader->icmp_type == 11) {
                                printf("ICMP Type 3 and 11 shouldn't be here, ignoring...\n");
                                return 0;
                        }

                        /* If it is a Echo Request (Type 8, Code 0):
                           Reply with a Echo _Reply_ (Type 0, Code 0) */
                        if (icmpHeader->icmp_type == 8 && icmpHeader->icmp_code == 0) {
                                Debug("Receive an ICMP Echo request\n");
                                return ICMP_Message0(sr, packet, interface, 0);
                        }
                }
        }

        return 0;
}
/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
                     uint8_t * packet /* lent */,
                     unsigned int len,
                     char* interface /* lent */)
{
        /* REQUIRES */
        assert(sr);
        assert(packet);
        assert(interface);

        printf("*** -> Received packet of length %d \n",len);

        /* Variables */
        size_t ethernetHeaderSize = sizeof(sr_ethernet_hdr_t);

        /* Check packet type */
        uint16_t frameType = ethertype(packet);

        /* Ethernet Frame Sanity Check */
        if (len < ethernetHeaderSize) {
                fprintf(stderr, "Sanity Check: Ethernet Frame has invalid length!\n");
                return;
        }

        /* If it is not a IP packet or a ARP Packet we don't know what to do */
        if (frameType != ethertype_ip && frameType != ethertype_arp) {
                fprintf(stderr, "We can't tell what this frame is!\n");
                return;
        }

        else{

                /* If we detect that the frame is an IP, send the packet to process_IP */
                if (frameType == ethertype_ip) {
                        printf("Got an IP packet going to interface: %s\n", interface);
                        process_IP(sr, packet, len, interface);
                        return;
                }

                /* If we detect that the frame is an ARP, send the packet to process_ARP */
                if (frameType == ethertype_arp) {
                        printf("Got an ARP packet going to interface: %s\n", interface);
                        process_ARP(sr, packet, len, interface);
                        return;
                }
        }

}  /* end sr_ForwardPacket */
