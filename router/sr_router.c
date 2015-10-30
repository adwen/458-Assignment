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

/* Method to handle ICMP Type 0 messages */
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

        /* Case where we receive a IP */
        if (packet_type == ethertype_ip) {
                printf("Packet is a IP packet!\n");
                process_IP(sr, packet, len, interface);
        }

        /* Case where we receive a ARP */
        if (packet_type == ethertype_arp) {

                printf("Packet is a ARP!\n");
                /* Pass all the parameters to the ARP function */
                process_ARP(sr, packet, len, interface);
        }

        else{
                /* Invalid header */
                fprintf(stderr, "Invalid Header!\n");
        }
        return;
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

        int ethernetHeaderSize = sizeof(sr_ethernet_hdr_t);
        sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(arpPacket + ethernetHeaderSize);

        /* Check if ARP packet is for me.
        If it is, process and reply. Otherwise, discard. */
        struct sr_if* this_interface = sr_get_interface(sr, interface);

        if (arp_header->ar_tip != this_interface->ip)
            return 1;

        switch (arp_header->ar_op)
        {
            case arp_op_request:
                /* Recieved an ARP request */
                unsigned int new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
                void * new_packet = malloc(new_len);
                bzero(new_packet, new_len);
                sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) new_packet;
                memset(eth_hdr->ether_dhost, 0xFF, ETHER_ADDR_LEN);
                memcpy(eth_hdr->shost, sr_if->addr, ETHER_ADDR_LEN);
                eth_hdr->ethertype = htons(sr_ethertype.ethertype_arp);

                sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) (new_packet + sizeof(sr_ethernet_hdr_t));
                arp_hdr->arp_hln = ETHER_ADDR_LEN;
                arp_hdr->arp_pln = 4;
                arp_hdr->arp_hrd = htons(sr_arp_hrd_format.arp_hrd_ethernet);
                arp_hdr->arp_pro = htons(sr_arp_opcode.arp_op_reply);
                memcpy(arp_hdr->ar_sha, sr_if->addr, ETHER_ADDR_LEN);
                memcpy(arp_hdr->ar_tha, sr_if->ar_tha, ETHER_ADDR_LEN);
                arp_hdr->ar_sip = if_st->ip;
                arp_hdr->ar_tip = ar_tip;

                int ret = sr_send_packet(sr, new_packet, new_len, interface);
                free(new_packet);
                return ret;
                break;
            case arp_op_reply:
                /* Recieved an ARP reply */
                if (sr_if){
                    tmp = sr_arpcache_insert(&(sr->cache), arp_header->ar_sha, arp_header->ar_sip));
                } else {
                    tmp = sr->cache.requets;
                    while (tmp) {
                        if (tmp->ip != arp_hdr->ar_sip) tmp = tmp->next;
                    }
                    if (!tmp) {
                        fprintf(stderr, "ARP not for us.\n");
                        return -1;
                    }
                }


                struct sr_packet *temppacket = tmp->packets;
                while (temppacket) {
                    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) temppacket->buf;
                    struct sr_if *sending_if = sr_get_interface(sr, interface);
                    memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                    memcpy(eth_hdr->ether_shost, sending_if->addr, ETHER_ADDR_LEN);
                    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (temppacket->buf + sizeof(sr_ethernet_hdr_t));
                    ip_hdr->ip_sum = 0;
                    ip_hdr->ip_ttl -= 1;
                    ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl*4);
                    sr_send_packet(sr, temppacket->buf, temppacket->len, interface);
                    temppacket = temppacket->next;
                }

                sr_arpreq_destroy(&(sr->cache), tmp);
                break;

            default:
                fprintf(stderr, "Incorrect ARP operation!\n");
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
        } printf("IP Header passed minimum length test!\n");

        /* Construct the IP Header and deal with it */
        sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(ipPacket + ethernetHeaderSize);
        printf("Created IP header!\n");
        /* Sanity Check #2: Verify checksums via cksum() from sr_utils.c */
        uint16_t cksum_result = cksum(ip_header, ip_header->ip_hl);
        if (!cksum_result) {
                fprintf(stderr, "Checksum failed!\n");
                return -1;
        } printf("IP Header passed checksum test!\n");

        /* Check the destination */
        struct sr_if *destination = sr_get_ip_interface(sr, ntohl(ip_header->ip_dst));

        /* If the packet is for us: We process it */
        if (destination){
            printf("Packet is for us! \n");

            /* Check the protocol type */
            uint8_t protocol_type = ip_header->ip_p;

            /* If it is an ICMP protocol */
            if (protocol_type == ip_protocol_icmp){
                printf("This IS a ICMP protocol!\n");

                /* Construct the header **/
                sr_icmp_hdr_t *ICMP_header = (sr_icmp_hdr_t *) (ipPacket + ethernetHeaderSize + ipHeaderSize);

                /* If it is not a echo request, we dont' do anything? */
                if(ICMP_header->icmp_code != 0 || ICMP_header->icmp_code != 8){
                    printf("Not an echo request!\n");
                    return -1;
                }

                /* Check the checksum of the ICMP Header */
                uint32_t icmp_checksum = ICMP_header->icmp_sum;
                uint32_t ver_sum = cksum((uint8_t *) ICMP_header, ntohs(ip_header->ip_len) - ipHeaderSize);
                if (icmp_checksum != ver_sum){
                    fprintf(stderr, "ICMP checksum does not match! \n");
                    return -1;
                }

                /* If it is a echo request, we send it */
                if(ICMP_header->icmp_code == 0 || ICMP_header->icmp_code == 8){
                    printf("Echo request!\n");
                    /* Send it here */
                    type = 0; code = 0;
                    return ICMP_message0(sr, ipPacket, interface, type, code);
                }
            }

            /* If it is not a ICMP protocol */
            else if(protocol_type != ip_protocol_icmp){
                printf("This is not a ICMP Protocol!!!");
                /* This is either TCP or UDP: Send port unreachable, type 3, code 3 */
                type = 3; code = 3;
                return ICMP_message3(sr, ipPacket, interface, type, code);
            }
        }

        /* Otherwise, if the packet is not intended for us */
        else if (!destination){
            printf("This packet is not for us! We will just pass it on!\n");
            /* Datagram should be forwarded: Decrement the TTL */

            /* Check if decrementing will result in 0 */
            uint8_t current_TTL = ip_header->ip_ttl;
            if ((current_TTL - 1) <= 0){
                printf("TTL: TIME EXCEEDED! Discarding Packet\n");
                /* Need to send a icmp message with type 11, code 0 */
                type = 11; code = 0;
                return ICMP_message11(sr, ipPacket, interface, type, code);
            } printf("TTL check OK! \n");

            /* Decrement TTL */
            ip_header->ip_ttl = ip_header->ip_ttl - 1;
            /* Check/Update Checksum */
            ip_header->ip_sum = cksum(ip_header, ip_header->ip_hl * 4);
            /* Now that we know we can forward it since TTL allows it */
            /* We need to get a routing table */
            struct sr_rt *currentRoutingTable = sr->routing_table;
            printf("Got routing table!\n");

            /* Traverse through the table and find the correct destination */
            while (currentRoutingTable != NULL){
                /* Destination IP logical AND with a subnetmask == subnet address */
                uint32_t packetDestination = ip_header->ip_dst & currentRoutingTable->mask.s_addr;

                /* Check if it matches a routing table Destination */
                if (packetDestination == currentRoutingTable->dest.s_addr){
                    struct sr_if* interface = sr_get_interface(sr, currentRoutingTable->interface);
                }

                /* not sure what to do here */

                /* Need to go to the next entry in table after everything is done*/
                currentRoutingTable = currentRoutingTable->next;
            }

            /* If we leave the while loop without jumping to another function to destination couldnt be reached */
            /* send a message with type 3, code 1 */
            type = 3; code = 1;
            return ICMP_message3(sr, ipPacket, interface, type, code);
        }

        return 0; /* Temp: So make gcc doesn't lose it's shit */
}
