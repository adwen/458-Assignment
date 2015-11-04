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

} /* -- sr_init -- */

/* Method to handle ICMP Type 0 messages */
int ICMP_message0(struct sr_instance* sr, uint8_t *ICMP_Packet, char* interface, uint8_t type, uint8_t code){
    printf("Inside ICMP0 handling Block!\n");
    /* Useful Variables */
    int ethernetHeaderSize = sizeof(sr_ethernet_hdr_t);
    int ipHeaderSize = sizeof(sr_ip_hdr_t);
    int icmpHeaderSize = 0;  /* For now */
    /* Get the incoming packet passed to this function */
    sr_ip_hdr_t *pkt = (sr_ip_hdr_t *) (ICMP_Packet + ethernetHeaderSize);

    /* Structures defined in sr_protocol.h */
    /* if this part is wrong its probably cuz i defined the structures wrong size */
    /* I wrote them in sr_protocol.h from http://www.networksorcery.com/enp/protocol/icmp.htm */
    printf("TYPE 0 ICMP\n");
    icmpHeaderSize = ntohs(pkt->ip_len) - pkt->ip_hl*4;


    /* Create the new packet now */
    printf("Creating Packet to send!\n");
    struct sr_if *iface = sr_get_interface(sr, interface);
    unsigned int length = ipHeaderSize + ethernetHeaderSize + icmpHeaderSize;
    uint8_t *newPacket = (uint8_t *) malloc(length);
    bzero(newPacket, length); /* I got this from stackovrflow, not really sure why though */

    /* Create the Ethernet header of the packet */
    printf("Creating Ethernet Header!\n");
    sr_ethernet_hdr_t *new_e = (sr_ethernet_hdr_t *) newPacket;
    sr_ethernet_hdr_t *current = (sr_ethernet_hdr_t *) ICMP_Packet;
    new_e->ether_type = htons(ethertype_ip);
    /* Source = dest reversal by literally cross copying data */
    memcpy(new_e->ether_shost, current->ether_dhost, ETHER_ADDR_LEN); /* New dest = old source */
    memcpy(new_e->ether_dhost, current->ether_shost, ETHER_ADDR_LEN); /* New dest = old source */


    /* Create the IP header of the packet */
    printf("Creating IP Header!\n");
    sr_ip_hdr_t *ip = (sr_ip_hdr_t *) (newPacket + ethernetHeaderSize);
    ip->ip_dst = pkt->ip_src; /* Send back to where we got it from */
    ip->ip_hl = 5;
    ip->ip_id = pkt->ip_id;
    ip->ip_p = ip_protocol_icmp; /* Sending icmp protocol */
    ip->ip_src = iface->ip;
    ip->ip_tos = pkt->ip_tos;
    ip->ip_len = htons(length - ethernetHeaderSize);
    ip->ip_sum = cksum(newPacket + ethernetHeaderSize, ip->ip_hl * 4);
    ip->ip_off = 0;
    ip->ip_ttl = INIT_TTL;
    ip->ip_v = 4;

    /* Create the ICMP header of the packet */ int retval = 0;
    printf("TYPE 0 ICMP operations\n");
    /* Create the type 0 ICMP packet */
    printf("Creating type 0 icmp packet!\n");
    sr_icmp_t0_hdr_t *type0 = (sr_icmp_t0_hdr_t *) (newPacket + ethernetHeaderSize + ipHeaderSize);
    /* Get the current icmp header to copy values*/
    sr_icmp_t0_hdr_t *current0 = (sr_icmp_t0_hdr_t *) (ICMP_Packet + ethernetHeaderSize + ipHeaderSize);
    /* Set the values */
    type0->icmp_type = type;
    type0->icmp_code = code;
    type0->icmp_sum = cksum(newPacket+ ethernetHeaderSize + ipHeaderSize, icmpHeaderSize);
    type0->icmp_identifier = current0->icmp_identifier;
    type0->seqnum = current0->seqnum;
    memcpy(type0->data, current0->data, ICMP_DATA_SIZE);
    printf("Done creating type 0 ICMP!\n");

    /* Send the Packet */
    retval = sr_send_packet(sr, newPacket, length, interface);
    free(newPacket);

    return retval;
}

/* Method to handle ICMP Type 3 messages */
int ICMP_message3(struct sr_instance* sr, uint8_t *ICMP_Packet, char* interface, uint8_t type, uint8_t code){
    printf("Inside ICMP handling Block!\n");
    /* Useful Variables */
    int ethernetHeaderSize = sizeof(sr_ethernet_hdr_t);
    int ipHeaderSize = sizeof(sr_ip_hdr_t);
    int icmpHeaderSize = 0;  /* For now */
    /* Get the incoming packet passed to this function */
    sr_ip_hdr_t *pkt = (sr_ip_hdr_t *) (ICMP_Packet + ethernetHeaderSize);

    /* Structures defined in sr_protocol.h */
    /* if this part is wrong its probably cuz i defined the structures wrong size */
    /* I wrote them in sr_protocol.h from http://www.networksorcery.com/enp/protocol/icmp.htm */
    printf("TYPE 3 ICMP\n");
    icmpHeaderSize = sizeof(sr_icmp_t3_hdr_t);

    /* Create the new packet now */
    printf("Creating Packet to send!\n");
    struct sr_if *iface = sr_get_interface(sr, interface);
    unsigned int length = ipHeaderSize + ethernetHeaderSize + icmpHeaderSize;
    uint8_t *newPacket = (uint8_t *) malloc(length);
    bzero(newPacket, length); /* I got this from stackovrflow, not really sure why though */

    /* Create the Ethernet header of the packet */
    printf("Creating Ethernet Header!\n");
    sr_ethernet_hdr_t *new_e = (sr_ethernet_hdr_t *) newPacket;
    sr_ethernet_hdr_t *current = (sr_ethernet_hdr_t *) ICMP_Packet;
    new_e->ether_type = htons(ethertype_ip);
    /* Source = dest reversal by literally cross copying data */
    memcpy(new_e->ether_shost, current->ether_dhost, ETHER_ADDR_LEN); /* New dest = old source */
    memcpy(new_e->ether_dhost, current->ether_shost, ETHER_ADDR_LEN); /* New dest = old source */


    /* Create the IP header of the packet */
    printf("Creating IP Header!\n");
    sr_ip_hdr_t *ip = (sr_ip_hdr_t *) (newPacket + ethernetHeaderSize);
    ip->ip_dst = pkt->ip_src; /* Send back to where we got it from */
    ip->ip_hl = 5;
    ip->ip_id = pkt->ip_id;
    ip->ip_p = ip_protocol_icmp; /* Sending icmp protocol */
    ip->ip_src = iface->ip;
    ip->ip_tos = pkt->ip_tos;
    ip->ip_len = htons(length - ethernetHeaderSize);
    ip->ip_sum = cksum(newPacket + ethernetHeaderSize, ip->ip_hl * 4);
    ip->ip_off = 0;
    ip->ip_ttl = INIT_TTL;
    ip->ip_v = 4;

    /* Create the ICMP header of the packet */ int retval = 0;


    printf("TYPE 3 ICMP operations!\n");
    printf("Creating type 3 icmp packet!\n");
    sr_icmp_t3_hdr_t *type3 = (sr_icmp_t3_hdr_t *) (newPacket + ethernetHeaderSize + ipHeaderSize);
    type3->icmp_type = type;
    type3->icmp_code = code;
    type3->icmp_sum = cksum(newPacket+ ethernetHeaderSize + ipHeaderSize, icmpHeaderSize);
    memcpy(type3->data, ICMP_Packet + ethernetHeaderSize, ip->ip_hl*4 + 8);
    printf("Done creating type 3 ICMP!\n");

    /* Send the Packet */
    retval = sr_send_packet(sr, newPacket, length, interface);
    free(newPacket);

    return retval;
}

/* Method to handle ICMP Type 11 messages */
int ICMP_message11(struct sr_instance* sr, uint8_t *ICMP_Packet, char* interface, uint8_t type, uint8_t code){
    printf("Inside ICMP handling Block!\n");
    /* Useful Variables */
    int ethernetHeaderSize = sizeof(sr_ethernet_hdr_t);
    int ipHeaderSize = sizeof(sr_ip_hdr_t);
    int icmpHeaderSize = 0;  /* For now */
    /* Get the incoming packet passed to this function */
    sr_ip_hdr_t *pkt = (sr_ip_hdr_t *) (ICMP_Packet + ethernetHeaderSize);

    /* Structures defined in sr_protocol.h */
    /* if this part is wrong its probably cuz i defined the structures wrong size */
    /* I wrote them in sr_protocol.h from http://www.networksorcery.com/enp/protocol/icmp.htm */
    printf("TYPE 11 ICMP\n");
    icmpHeaderSize = sizeof(sr_icmp_t11_hdr_t);

    /* Create the new packet now */
    printf("Creating Packet to send!\n");
    struct sr_if *iface = sr_get_interface(sr, interface);
    unsigned int length = ipHeaderSize + ethernetHeaderSize + icmpHeaderSize;
    uint8_t *newPacket = (uint8_t *) malloc(length);
    bzero(newPacket, length); /* I got this from stackovrflow, not really sure why though */

    /* Create the Ethernet header of the packet */
    printf("Creating Ethernet Header!\n");
    sr_ethernet_hdr_t *new_e = (sr_ethernet_hdr_t *) newPacket;
    sr_ethernet_hdr_t *current = (sr_ethernet_hdr_t *) ICMP_Packet;
    new_e->ether_type = htons(ethertype_ip);
    /* Source = dest reversal by literally cross copying data */
    memcpy(new_e->ether_shost, current->ether_dhost, ETHER_ADDR_LEN); /* New dest = old source */
    memcpy(new_e->ether_dhost, current->ether_shost, ETHER_ADDR_LEN); /* New dest = old source */


    /* Create the IP header of the packet */
    printf("Creating IP Header!\n");
    sr_ip_hdr_t *ip = (sr_ip_hdr_t *) (newPacket + ethernetHeaderSize);
    ip->ip_dst = pkt->ip_src; /* Send back to where we got it from */
    ip->ip_hl = 5;
    ip->ip_id = pkt->ip_id;
    ip->ip_p = ip_protocol_icmp; /* Sending icmp protocol */
    ip->ip_src = iface->ip;
    ip->ip_tos = pkt->ip_tos;
    ip->ip_len = htons(length - ethernetHeaderSize);
    ip->ip_sum = cksum(newPacket + ethernetHeaderSize, ip->ip_hl * 4);
    ip->ip_off = 0;
    ip->ip_ttl = INIT_TTL;
    ip->ip_v = 4;

    /* Create the ICMP header of the packet */ int retval = 0;
    printf("TYPE 11 ICMP operations\n");
    printf("Creating type 11 icmp packet!\n");
    sr_icmp_t11_hdr_t *type11 = (sr_icmp_t11_hdr_t *) (newPacket + ethernetHeaderSize + ipHeaderSize);
    type11->icmp_type = type;
    type11->icmp_code = code;
    type11->icmp_sum = cksum(newPacket+ ethernetHeaderSize + ipHeaderSize, icmpHeaderSize);
    memcpy(type11->data, ICMP_Packet + ethernetHeaderSize, ip->ip_hl*4 + 8);
    printf("Done creating type 11 ICMP!\n");
    /* Send the Packet */
    retval = sr_send_packet(sr, newPacket, length, interface);
    free(newPacket);
    return retval;
}


/* return send_arp(sr, arp_op_reply, arp_header->ar_sip, arp_header->ar_sha);*/
/* Create a new ARP packet and send it */
int send_arp(struct sr_instance* sr, unsigned short opcode, uint32_t sender_ip,
    unsigned char target_hardware_addr[ETHER_ADDR_LEN])
{
        printf("\nStarting ARP Reply function: Creating the Reply ARP Packet!\n");
        /* Placeholder for packet */
        size_t ethernetHeaderSize = sizeof(sr_ethernet_hdr_t);
        size_t arpHeaderSize = sizeof(sr_arp_hdr_t);
        unsigned int arpLength = ethernetHeaderSize + arpHeaderSize;
        uint8_t *arpPacket = (uint8_t *) malloc(arpLength);
        bzero(arpPacket, arpLength);

        /* Get the interface to send to */
        printf("\t Getting interface!\n");
        char *sending_interface = NULL;
        struct sr_rt *table_entry = sr->routing_table;
        while (table_entry != NULL){
            if ( (sender_ip & table_entry->mask.s_addr) ==  table_entry->dest.s_addr){
                sending_interface = table_entry->interface;
            }
            table_entry = table_entry->next;
        }
        struct sr_if *interface2 = sr_get_interface(sr, sending_interface);

        /* Create the Ethernet Frame */
        printf("\t Creating Ethernet Frame!\n");
        sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *) arpPacket;
        if (opcode == arp_op_request){
            memset(ethernet_header->ether_dhost, 0xff, ETHER_ADDR_LEN);
        }
        else{
            memcpy(ethernet_header->ether_dhost, target_hardware_addr, ETHER_ADDR_LEN);
        }
        memcpy(ethernet_header->ether_shost, interface2->addr, ETHER_ADDR_LEN);
        ethernet_header->ether_type = htons(ethertype_arp);

        /* Create the ARP Header */
        printf("\t Creating ARP Header!\n");
        sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *) (arpPacket + ethernetHeaderSize);
        arp_header->ar_hrd = htons(arp_hrd_ethernet);
        arp_header->ar_pro = htons(ethertype_ip);
        arp_header->ar_hln = ETHER_ADDR_LEN;
        arp_header->ar_pln = 4;
        arp_header->ar_op = htons(opcode);
        memcpy(arp_header->ar_sha, interface2->addr, ETHER_ADDR_LEN);
        arp_header->ar_sip = interface2->ip;
        memcpy(arp_header->ar_tha, target_hardware_addr, ETHER_ADDR_LEN);
        arp_header-> ar_tip = sender_ip;
        printf("\t\tDone Creating ARP Packet, sending the ARP Packet out!\n");

        /* Send the packet out */
        int retval = sr_send_packet(sr, arpPacket, arpLength, sending_interface);
        printf("\t\tARP Packet Sent!\n");
        free(arpPacket);
        return retval;
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

        printf("\n*** -> Received packet of length %d \n",len);

        uint16_t packet_type = ethertype(packet);
        /* fill in code here */
        /* SANITY CHECK: Minimum Length is valid
           Supposed ethernet frame length defined in sr_pr otocol.h
           This denotes a frame that is insufficient length */
        if (len < sizeof(sr_ethernet_hdr_t)) {
                fprintf(stderr, "Packet failed Sanity Check #1: ");
                return;
        } printf("Passed initial length test => Valid Ethernet Frame!\n");

        switch(packet_type){
            case ethertype_ip:
                printf("Packet is an IP Packet!\n");
                process_IP(sr, packet, len, interface);
                printf("FINISHED PROCESS IP\n");
                break;

            case ethertype_arp:
                printf("Packet is an ARP!\n");
                process_ARP(sr, packet, len, interface);
                printf("FINISHED PROCESS ARP\n");
                break;

            default:
                printf("INVALID HEADER!\n");
                break;
        }
}/* end sr_ForwardPacket */

/* Function to process the logic behind the ARP Packet */
int process_ARP(struct sr_instance* sr,
                uint8_t * arpPacket /* lent */,
                unsigned int arpLength,
                char* interface /* lent */)
{
        printf("Entered ARP packet processing block \n");
        /* Sanity Check */
        /* Check the correct length of a ARP packet
         * arpLength = Ethernet Header + Arp Header
         * both values can be found in sr_protocol.h */
        int minimum_arpLength = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);

        if (arpLength < minimum_arpLength) {
                fprintf(stderr, "invalid ARP length");
                return -1;
        } printf("ARP Header passed minimum length test!\n");

        size_t ethernetHeaderSize = sizeof(sr_ethernet_hdr_t);
        sr_arp_hdr_t* arp_header = (sr_arp_hdr_t *)(arpPacket + ethernetHeaderSize);

        /* Check if ARP packet is for me.
        If it is, process and reply. Otherwise, discard. */
        struct sr_if *this_interface = sr_get_ip_interface(sr, arp_header->ar_tip);

        /* Check if the arp is a reply or a request */

        /* Request Case */
        if (arp_header->ar_op == htons(arp_op_request)){
            printf("Received a ARP Request!\n");

            /* ARP Request not for this router */
            if (!this_interface){
                printf("\tARP Request destination is not this router!\n");
                return -1;
            }

            /* If it is for this router, we need to send a reply */
            else{
                printf("\tARP Request is for this router: Send Reply");
                return send_arp(sr, arp_op_reply, arp_header->ar_sip, arp_header->ar_sha);
            }

            /* ARP Request not for this router */
            if (!this_interface){
                printf("\tARP Request destination is not this router!\n");
                return -1;
            }
        }

        /* Reply Case */
        if (arp_header->ar_op != htons(arp_op_request)){
            printf("Received a ARP Reply!\n");
            struct sr_arpreq *request = NULL;

            /* If it is for our router, we just cache it */
            if (this_interface){
                printf("\t ARP Reply for our Router: Caching immediately!\n");
                request = sr_arpcache_insert(&(sr->cache), arp_header->ar_sha, arp_header->ar_sip);
            }

            /* If it is not for our router, we have cache only if IP is found in our Router's interface's IPs */
            else if (!this_interface){
                printf("\t ARP Reply not for our Router: Check if our router has it's IP!\n");
                /* Get our Router's interface's IPs */
                request = sr->cache.requests;
                /* Check for a match */
                while (request != NULL){
                    if (request->ip != arp_header->ar_sip){
                        request = request->next;
                    }
                }
                /* If there is no match, request will iterate until it is null */
                if (request == NULL){
                    printf("\t\t Destination IP not found in our Router, can't do anything with it!\n");
                    return -1;
                }
            } /* End if !this_interface */

            /* After Caching, need to send it out*/
            struct sr_packet *request_packets = request->packets;
            printf("\t Sending out cached packets!\n");
            while (request_packets != NULL){
                /* Get the sending interface */
                struct sr_if *sending_interface = sr_get_interface(sr, interface);

                /* Create Ethernet Header*/
                sr_ethernet_hdr_t * ethernet_header = (sr_ethernet_hdr_t *) request_packets->buf;
                memcpy(ethernet_header->ether_shost, sending_interface->addr, ETHER_ADDR_LEN);
                memcpy(ethernet_header->ether_dhost, arp_header->ar_sha, ETHER_ADDR_LEN);

                /* Create IP Header */
                sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (request->packets->buf + ethernetHeaderSize);
                ip_header->ip_sum = 0;
                ip_header->ip_sum = cksum(ip_header, ip_header->ip_hl*4);
                ip_header->ip_ttl = ip_header->ip_ttl - 1;

                /* Send current Packet */
                sr_send_packet(sr, request_packets->buf, request_packets->len, interface);
                printf("\t\t\t Request packet sent!\n");

                /* Traverse to next request Packet */
                request_packets = request_packets->next;
            }
            printf("Freeing Memory!\n");
            sr_arpreq_destroy(&(sr->cache), request);
        }
        return 0; /* Temp: So make gcc doesn't lose it's shit */
}


/* Function to process the logic behind the IP Packet */
int process_IP(struct sr_instance* sr,
               uint8_t * ipPacket /* lent */,
               unsigned int ipLength,
               char* interface /* lent */)
{
        printf("Entered IP packet processing block \n");

        /* Variables */
        uint8_t type = 0; uint8_t code = 0;
        /* Sanity Check */
        /* Check the correct length of a IP packet
         * ipLength = IP Header + IP Header
         * both values can be found in sr_protocol.h */
        int ethernetHeaderSize = sizeof(sr_ethernet_hdr_t);
        int ipHeaderSize = sizeof(sr_ip_hdr_t);
        int minimum_ipLength = ethernetHeaderSize + ipHeaderSize;

        if (ipLength < minimum_ipLength) {
                fprintf(stderr, "invalid IP length!\n");
                return -1;
        } printf("\tIP Header passed minimum length test!\n");

        /* Construct the IP Header and deal with it */
        sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(ipPacket + ethernetHeaderSize);
        /* Sanity Check #2: Verify checksums via cksum() from sr_utils.c */
        uint16_t cksum_result = cksum(ip_header, ip_header->ip_hl);
        if (!cksum_result) {
                fprintf(stderr, "Checksum failed!\n");
                return -1;
        } printf("\tIP Header passed checksum test!\n");

        /* Check the destination */
        struct sr_if *destination = sr_get_ip_interface(sr, ntohl(ip_header->ip_dst));

        /* If the packet is for us: We process it */
        if (destination){
            printf("\tPacket is for us! \n");

            /* Check the protocol type */
            uint8_t protocol_type = ip_header->ip_p;

            /* If it is an ICMP protocol */
            if (protocol_type == ip_protocol_icmp){
                printf("\t\tThis IS a ICMP protocol!\n");

                /* Construct the header **/
                sr_icmp_hdr_t *ICMP_header = (sr_icmp_hdr_t *) (ipPacket + ethernetHeaderSize + ipHeaderSize);

                /* If it is not a echo request, we dont' do anything? */
                if(ICMP_header->icmp_code != 0 || ICMP_header->icmp_code != 8){
                    printf("\t\t\tNot an echo request! Ending!\n");
                    return -1;
                }

                /* Check the checksum of the ICMP Header */
                uint32_t icmp_checksum = ICMP_header->icmp_sum;
                uint32_t ver_sum = cksum((uint8_t *) ICMP_header, ntohs(ip_header->ip_len) - ipHeaderSize);
                if (icmp_checksum != ver_sum){
                    fprintf(stderr, "\t\t\tICMP checksum does not match! \n");
                    return -1;
                }

                /* If it is a echo request, we send it */
                if(ICMP_header->icmp_code == 0 || ICMP_header->icmp_code == 8){
                    printf("\t\t\tEcho request!\n");
                    /* Send it here */
                    type = 0; code = 0;
                    printf("\t\t\tSending ICMP Message Type 0\n");
                    return ICMP_message0(sr, ipPacket, interface, type, code);
                }
            }

            /* If it is not a ICMP protocol */
            else if(protocol_type != ip_protocol_icmp){
                printf("\t\tThis is not a ICMP Protocol!!! Sending Type 3!\n");
                /* This is either TCP or UDP: Send port unreachable, type 3, code 3 */
                type = 3; code = 3;
                printf("\t\tSending ICMP Message Type 3\n");
                return ICMP_message3(sr, ipPacket, interface, type, code);
            }
        }

        /* Otherwise, if the packet is not intended for us */
        /* Find out which entry in the routing table has the longest prefix match with the destination IP address. */
        /* Check the ARP cache for the next-hop MAC address corresponding to the next-hop IP. If it’s there, send it.  */
        /* Otherwise, send an ARP request for the next-hop IP (if one hasn’t been sent within the last second), and add the packet to the queue of packets waiting on this ARP request. */
        else if (!destination){
            printf("\tThis packet is not for us! We will just pass it on!\n");
            /* Datagram should be forwarded: Decrement the TTL */

            /* Check if decrementing will result in 0 */
            uint8_t current_TTL = ip_header->ip_ttl;
            if ((current_TTL - 1) <= 0){
                printf("\t\tTTL: TIME EXCEEDED! Discarding Packet\n");
                /* Need to send a icmp message with type 11, code 0 */
                type = 11; code = 0;
                printf("\t\tSending ICMP Message Type 11\n");
                return ICMP_message11(sr, ipPacket, interface, type, code);
            } printf("\t\tTTL check OK! \n");

            /* Now that we know we can forward it since TTL allows it */
            /* We need to get a routing table */
            struct sr_rt *currentRoutingTable = sr->routing_table;
            printf("\t\tGot routing table!\n");

            /* Traverse through the table and find the correct destination */
            while (currentRoutingTable != NULL){
                /* Destination IP logical AND with a subnetmask == subnet address */
                uint32_t packetDestination = ip_header->ip_dst & currentRoutingTable->mask.s_addr;

                /* Check if it matches a routing table Destination */
                printf("\t\t\tFinding Routing Table Match!\n");
                if (packetDestination == currentRoutingTable->dest.s_addr){
                    struct sr_if* dest_interface = sr_get_interface(sr, currentRoutingTable->interface);
                    sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *) ipPacket;
                    memcpy(ethernet_header->ether_shost, dest_interface->addr, ETHER_ADDR_LEN);

                    /* Check the ARP cache for the next-hop MAC address corresponding to the next-hop IP. */
                    /* struct sr_arpentry *arp_e = sr_arpcache_lookup(&(sr->cache), rt_node->gw.s_addr); */
                    struct sr_arpentry *arp_match = sr_arpcache_lookup(&(sr->cache), currentRoutingTable->gw.s_addr);
                    /* If it’s there, send it.  */
                    if (arp_match != NULL){
                        memcpy(ethernet_header->ether_dhost, arp_match->mac, ETHER_ADDR_LEN);
                        free(arp_match);
                        /* Decrement TTL */
                        ip_header->ip_ttl = ip_header->ip_ttl - 1;
                        /* Check/Update Checksum */
                        ip_header->ip_sum = 0;
                        ip_header->ip_sum = cksum(ip_header, ip_header->ip_hl*4);
                        printf("\t\t\t\tMatch Found: Sending IP Packet !\n");
                        return sr_send_packet(sr, ipPacket, ipLength, currentRoutingTable->interface);
                    }

                    /* Otherwise, send an ARP request for the next-hop IP ,
                    and add the packet to the queue of packets waiting on this ARP request. */
                    else if (arp_match == NULL){
                        printf("\t\t\t\tMatch not Found: Send ARP request for next-hop IP and queue!\n");
                        struct sr_arpreq *queuereq = sr_arpcache_queuereq(&(sr->cache), currentRoutingTable->gw.s_addr,
                        ipPacket, ipLength, interface);

                        /* Check if ARP Request has been sent within last second */
                        double time_difference = difftime(time(NULL), queuereq->sent);
                        uint32_t sent = queuereq->times_sent;
                        if (time_difference > 1){
                            /*  Check if it has been sent 5 times */
                            if (sent > 5){
                                printf("\t\t\t\t\tARP Request has been sent 5 times with no response!\n"
                                "\t\t\t\t\tSending destination host unreachable ICMP to all senders waiting "
                                "for this ARP!\n");
                                /* Send ICMP type 3, code 1 for all packets in the request*/
                                type = 3; code = 1;
                                struct sr_packet *packets = queuereq->packets;
                                while (packets!=NULL){
                                    printf("\t\t\t\t\tSending ICMP Message Type 3!\n");
                                    ICMP_message3(sr, packets->buf, packets->iface, type, code);
                                    packets = packets->next;
                                } sr_arpreq_destroy( &(sr->cache), queuereq);
                            }
                            else{
                                printf("\t\t\t\t\tNow sending the ARP Request!\n");
                                /* FIND ME */
                                /*int send_arp(struct sr_instance* sr, unsigned short opcode, uint32_t sender_ip,
                                    unsigned char target_hardware_addr[ETHER_ADDR_LEN]) */
                                unsigned char sender_hardware_address[ETHER_ADDR_LEN];
                                memset(sender_hardware_address, 0, ETHER_ADDR_LEN);
                                send_arp(sr, arp_op_request, queuereq->ip, sender_hardware_address);
                                printf("\t\t\t\t\tARP PACKET SENT!!! Need to make changes in the cache..\n");

                                /* Reflect the time sent in the cache */
                                struct sr_arpcache *cache = &(sr->cache);
                                pthread_mutex_lock(&(cache->lock));
                                /* Critical Area */
                                queuereq->times_sent = queuereq->times_sent + 1;
                                queuereq->sent = time(NULL); /* Set sent time to current time */
                                pthread_mutex_unlock(&(cache->lock));
                            }
                        }
                        printf("\t\t\t\t\tReturning Zero...\n");
                        return 0;
                    }
                }
                /* Need to go to the next entry in table after everything is done*/
                currentRoutingTable = currentRoutingTable->next;
            }

            /* If we leave the while loop without jumping to another function to destination couldnt be reached */
            /* send a message with type 3, code 1 */
            if (currentRoutingTable == NULL){
                type = 3; code = 1;
                return ICMP_message3(sr, ipPacket, interface, type, code);
            }
        }

        return 0; /* Temp: So make gcc doesn't lose it's shit */
}
