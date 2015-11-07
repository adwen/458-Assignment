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

/* Logic to send an ICMP Message */
int ICMP_Message(struct sr_instance* sr, uint8_t *packet, char* interface, uint8_t type, uint8_t code) {
        printf("Sending ICMP!\n");
        size_t icmp_hdr_size = 0;
        size_t up_to_icmp_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
        sr_ip_hdr_t *ihdr_old = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

        switch(type) {
        case 0:
                icmp_hdr_size = ntohs(ihdr_old->ip_len) - ihdr_old->ip_hl*4;
                break;
        case 11:
                icmp_hdr_size = sizeof(sr_icmp_t11_hdr_t);
                break;
        case 3:
                icmp_hdr_size = sizeof(sr_icmp_t3_hdr_t);
                break;
        default:
                fprintf(stderr, "ICMP type not supported");
                return -1;
        }

        unsigned int len_new = up_to_icmp_size + icmp_hdr_size;
        uint8_t *packet_new = (uint8_t *) malloc(len_new);
        bzero(packet_new, len_new);
        struct sr_if *if_st = sr_get_interface(sr, interface);

        /* ethernet header */
        sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *) packet_new;
        sr_ethernet_hdr_t *ehdr_old = (sr_ethernet_hdr_t *) packet;
        memcpy(ehdr->ether_dhost, ehdr_old->ether_shost, ETHER_ADDR_LEN);
        memcpy(ehdr->ether_shost, ehdr_old->ether_dhost, ETHER_ADDR_LEN);
        ehdr->ether_type = htons(ethertype_ip);

        /* ip header */
        sr_ip_hdr_t *ihdr = (sr_ip_hdr_t *) (packet_new + sizeof(sr_ethernet_hdr_t));
        ihdr->ip_dst = ihdr_old->ip_src;
        ihdr->ip_hl = 5;
        ihdr->ip_id = 0;
        ihdr->ip_p = ip_protocol_icmp;
        ihdr->ip_src = if_st->ip;
        ihdr->ip_tos = 0;
        ihdr->ip_off = htons(IP_DF);
        ihdr->ip_ttl = INIT_TTL;
        ihdr->ip_v = 4;
        /* icmp */
        sr_icmp_t0_hdr_t *icmp_hdr_old = (sr_icmp_t0_hdr_t *) (packet + up_to_icmp_size);
        sr_icmp_t0_hdr_t *icmp_t0_hdr = (sr_icmp_t0_hdr_t *) (packet_new + up_to_icmp_size);
        sr_icmp_t11_hdr_t *icmp_t11_hdr = (sr_icmp_t11_hdr_t *) (packet_new + up_to_icmp_size);
        sr_icmp_t3_hdr_t *icmp_t3_hdr = (sr_icmp_t3_hdr_t *) (packet_new + up_to_icmp_size);

        switch(type) {
        case 0:
                icmp_t0_hdr->icmp_code = code;
                icmp_t0_hdr->icmp_type = type;
                icmp_t0_hdr->icmp_identifier = icmp_hdr_old->icmp_identifier;
                icmp_t0_hdr->seqnum = icmp_hdr_old->seqnum;
                icmp_t0_hdr->timestamp = icmp_hdr_old->timestamp;
                memcpy(icmp_t0_hdr->data, icmp_hdr_old->data, icmp_hdr_size - 10);
                icmp_t0_hdr->icmp_sum = cksum(packet_new + up_to_icmp_size, icmp_hdr_size);
                break;

        case 11:
                icmp_t11_hdr->icmp_code = code;
                icmp_t11_hdr->icmp_type = type;
                memcpy(icmp_t11_hdr->data, packet + sizeof(sr_ethernet_hdr_t), ihdr->ip_hl*4 + 8);
                icmp_t11_hdr->icmp_sum = cksum(packet_new + up_to_icmp_size, icmp_hdr_size);
                break;

        case 3:
                icmp_t3_hdr->icmp_code = code;
                icmp_t3_hdr->icmp_type = type;
                memcpy(icmp_t3_hdr->data, packet + sizeof(sr_ethernet_hdr_t), ihdr->ip_hl*4 + 8);
                icmp_t3_hdr->icmp_sum = cksum(packet_new + up_to_icmp_size, icmp_hdr_size);
                break;
        }

        ihdr->ip_len = htons(20 + icmp_hdr_size);
        ihdr->ip_sum = cksum(packet_new + sizeof(sr_ethernet_hdr_t), ihdr->ip_hl * 4);

        Debug("*** Sending an ICMP packet ***\n");
        /*print_hdr_icmp(packet_new + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));*/

        /* send now */
        int result = sr_send_packet(sr, packet_new, len_new, interface);
        free(packet_new);

        return result;
}

/* Logic to send an ARP Message */
int ARP_Message(
        struct sr_instance* sr,
        unsigned short opCode,
        unsigned char targetHardwareAddress[ETHER_ADDR_LEN],
        uint32_t targetIP)
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

        /* Construct the ARP Header from the packet */
        sr_arp_hdr_t *arpHeader = (sr_arp_hdr_t *)(packet + ethernetHeaderSize);

        /* Get the intended interface from the arpHeader */
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
                        return ARP_Message(sr, arp_op_reply, arpHeader->ar_sha, arpHeader->ar_sip);
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

        sr_ethernet_hdr_t *ethernetHeader = (sr_ethernet_hdr_t *) packet;
        sr_ip_hdr_t *ipHeader = (sr_ip_hdr_t *) (packet + ethernetHeaderSize);

        /* Sanity Check #2*/
        if(!cksum(ipHeader, ipHeader->ip_hl)) {
                fprintf(stderr, "Invalid IP header checksum");
                return -1;
        }

        struct sr_if *thisInterface = sr_get_ip_interface(sr, ipHeader->ip_dst);

        /* Target is for somewhere else */
        if (thisInterface == NULL) {

                if( (ipHeader->ip_ttl == 1) || (ipHeader->ip_ttl < 1)) {
                        printf("TTL Expired: Sending ICMP Type 11\n");
                        return ICMP_Message(sr, packet, interface, 11, 0);
                }

                printf("Packet needs to be routed elsewhere\n");

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
                                        handle_arpreq(sr, sr_arpcache_queuereq(&(sr->cache),
                                                                               routingEntryPointer->gw.s_addr, packet, len, interface));
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
                return ICMP_Message(sr, packet, interface, 3, 1);

        }

        /* Target is us! */
        if (thisInterface != NULL) {
                printf("IP Packet is for here\n");

                /* If it is not a ICMP msg => reply with ICMP Type 3 (Port UNreachable) */
                if (ipHeader->ip_p != ip_protocol_icmp) {
                        Debug("Not ICMP protocol");
                        return ICMP_Message(sr, packet, interface, 3, 3);  /* port unreachable */
                }

                /* ICMP Msg => we reply only if it is a echo request (Type 0)*/
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
                                return ICMP_Message(sr, packet, interface, 0, 0);
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
                fprintf(stderr, "Invalid Ethernet frame size");
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
