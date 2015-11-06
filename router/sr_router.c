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


int ICMP_Message0(struct sr_instance* sr, uint8_t *packet, char* interface, uint8_t type, uint8_t code) {
    printf("ICMP Type 0 Handler!\n");

    /* Construct the ICMP Header and Packet */
    size_t icmpHeaderSize = 0;
    size_t ethernetHeaderSize = sizeof(sr_ethernet_hdr_t);
    size_t ipHeaderSize = sizeof(sr_ip_hdr_t);
    size_t ethernet_and_ip = ethernetHeaderSize + ipHeaderSize;
	sr_ip_hdr_t *currentIP = (sr_ip_hdr_t *) (packet + ethernetHeaderSize);
    icmpHeaderSize = ntohs(currentIP->ip_len) - currentIP->ip_hl*4;
	unsigned int icmpLength = ethernet_and_ip + icmpHeaderSize;
	uint8_t *newPacket = (uint8_t *) malloc(icmpLength);
	bzero(newPacket, icmpLength);
	struct sr_if *currentInterface = sr_get_interface(sr, interface);

	/* Construct Ethernet header */
	sr_ethernet_hdr_t *ethernet = (sr_ethernet_hdr_t *) newPacket;
	sr_ethernet_hdr_t *currentEthernet = (sr_ethernet_hdr_t *) packet;
	memcpy(ethernet->ether_dhost, currentEthernet->ether_shost, ETHER_ADDR_LEN);
	memcpy(ethernet->ether_shost, currentEthernet->ether_dhost, ETHER_ADDR_LEN);
	ethernet->ether_type = htons(ethertype_ip);

    /* Construct IP header */
	sr_ip_hdr_t *ip = (sr_ip_hdr_t *) (newPacket + ethernetHeaderSize);
    /*ip->ip_hl = 5;
    ip->ip_v = 4;*/
    ip->ip_tos = 0;
    ip->ip_len = htons(20 + icmpHeaderSize);
    ip->ip_id = 0;
    ip->ip_off = htons(IP_DF);
    ip->ip_ttl = INIT_TTL;
    ip->ip_p = ip_protocol_icmp;
	ip->ip_dst = currentIP->ip_src;
	ip->ip_src = currentInterface->ip;
	ip->ip_sum = htons(cksum(newPacket + ethernetHeaderSize, ip->ip_hl * 4));

	/* Construct ICMP Type 0 header */
	sr_icmp_t0_hdr_t *currentICMP = (sr_icmp_t0_hdr_t *) (packet + ethernet_and_ip); /* Needed since we ECHO */
	sr_icmp_t0_hdr_t *icmpType0 = (sr_icmp_t0_hdr_t *) (newPacket + ethernet_and_ip);
	icmpType0->icmp_code = code;
	icmpType0->icmp_type = type;
	icmpType0->icmp_identifier = currentICMP->icmp_identifier;
	icmpType0->seqnum = currentICMP->seqnum;
	icmpType0->timestamp = currentICMP->timestamp;
	memcpy(icmpType0->data, currentICMP->data, icmpHeaderSize - 10);
	icmpType0->icmp_sum = cksum(newPacket + ethernet_and_ip, icmpHeaderSize);

	int retval = sr_send_packet(sr, newPacket, icmpLength, interface);
	free(newPacket);
	return retval;
}

int ICMP_Message3(struct sr_instance* sr, uint8_t *packet, char* interface, uint8_t type, uint8_t code) {
    printf("ICMP Type 3 Handler!\n");

    /* Construct the ICMP Header and Packet */
	size_t icmpHeaderSize = sizeof(sr_icmp_t3_hdr_t);
    size_t ethernetHeaderSize = sizeof(sr_ethernet_hdr_t);
    size_t ipHeaderSize = sizeof(sr_ip_hdr_t);
    size_t ethernet_and_ip = ethernetHeaderSize + ipHeaderSize;
	sr_ip_hdr_t *currentIP = (sr_ip_hdr_t *) (packet + ethernetHeaderSize);
	unsigned int icmpLength = ethernet_and_ip + icmpHeaderSize;
	uint8_t *newPacket = (uint8_t *) malloc(icmpLength);
	bzero(newPacket, icmpLength);
	struct sr_if *currentInterface = sr_get_interface(sr, interface);

    /* Construct Ethernet header */
	sr_ethernet_hdr_t *ethernet = (sr_ethernet_hdr_t *) newPacket;
	sr_ethernet_hdr_t *currentEthernet = (sr_ethernet_hdr_t *) packet;
	memcpy(ethernet->ether_dhost, currentEthernet->ether_shost, ETHER_ADDR_LEN);
	memcpy(ethernet->ether_shost, currentEthernet->ether_dhost, ETHER_ADDR_LEN);
	ethernet->ether_type = htons(ethertype_ip);

    /* Construct IP header */
	sr_ip_hdr_t *ip = (sr_ip_hdr_t *) (newPacket + ethernetHeaderSize);
    /*ip->ip_hl = 5;
    ip->ip_v = 4;*/
    ip->ip_tos = 0;
    ip->ip_len = htons(20 + icmpHeaderSize);
    ip->ip_id = 0;
    ip->ip_off = htons(IP_DF);
    ip->ip_ttl = INIT_TTL;
    ip->ip_p = ip_protocol_icmp;
	ip->ip_dst = currentIP->ip_src;
	ip->ip_src = currentInterface->ip;
	ip->ip_sum = htons(cksum(newPacket + ethernetHeaderSize, ip->ip_hl * 4));


    /* Consturc ICMP Type 3 header */
	sr_icmp_t3_hdr_t *icmpType3 = (sr_icmp_t3_hdr_t *) (newPacket + ethernet_and_ip);
	icmpType3->icmp_code = code;
	icmpType3->icmp_type = type;
	icmpType3->icmp_sum = cksum(newPacket + ethernet_and_ip, icmpHeaderSize);
    memcpy(icmpType3->data, packet + ethernetHeaderSize, ip->ip_hl*4 + 8);

	int retval = sr_send_packet(sr, newPacket, icmpLength, interface);
	free(newPacket);
	return retval;
}

int ICMP_Message11(struct sr_instance* sr, uint8_t *packet, char* interface, uint8_t type, uint8_t code) {
    printf("ICMP Type 11 Handler!\n");

    /* Construct the ICMP Header and Packet */
	size_t icmpHeaderSize = sizeof(sr_icmp_t11_hdr_t);
    size_t ethernetHeaderSize = sizeof(sr_ethernet_hdr_t);
    size_t ipHeaderSize = sizeof(sr_ip_hdr_t);
	size_t ethernet_and_ip = ethernetHeaderSize + ipHeaderSize;
	sr_ip_hdr_t *currentIP = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
	unsigned int icmpLength = ethernet_and_ip + icmpHeaderSize;
	uint8_t *newPacket = (uint8_t *) malloc(icmpLength);
	bzero(newPacket, icmpLength);
	struct sr_if *currentInterface = sr_get_interface(sr, interface);

    /* Construct Ethernet header */
	sr_ethernet_hdr_t *ethernet = (sr_ethernet_hdr_t *) newPacket;
	sr_ethernet_hdr_t *currentEthernet = (sr_ethernet_hdr_t *) packet;
	memcpy(ethernet->ether_dhost, currentEthernet->ether_shost, ETHER_ADDR_LEN);
	memcpy(ethernet->ether_shost, currentEthernet->ether_dhost, ETHER_ADDR_LEN);
	ethernet->ether_type = htons(ethertype_ip);

    /* Construct IP header */
	sr_ip_hdr_t *ip = (sr_ip_hdr_t *) (newPacket + ethernetHeaderSize);
    /*ip->ip_hl = 5;
    ip->ip_v = 4;*/
    ip->ip_tos = 0;
    ip->ip_len = htons(20 + icmpHeaderSize);
    ip->ip_id = 0;
    ip->ip_off = htons(IP_DF);
    ip->ip_ttl = INIT_TTL;
    ip->ip_p = ip_protocol_icmp;
	ip->ip_dst = currentIP->ip_src;
	ip->ip_src = currentInterface->ip;
	ip->ip_sum = htons(cksum(newPacket + ethernetHeaderSize, ip->ip_hl * 4));

    /* Construct ICMP Type 11header */
	sr_icmp_t11_hdr_t *icmpType11 = (sr_icmp_t11_hdr_t *) (newPacket + ethernet_and_ip);
	icmpType11->icmp_code = code;
	icmpType11->icmp_type = type;
	icmpType11->icmp_sum = cksum(newPacket + ethernet_and_ip, icmpHeaderSize);
    memcpy(icmpType11->data, packet + ethernetHeaderSize, ip->ip_hl*4 + 8);

	int retval = sr_send_packet(sr, newPacket, icmpLength, interface);
	free(newPacket);
	return retval;
}


/* Create a new ARP packet and send it */
int send_arp(struct sr_instance* sr, unsigned short opcode, uint32_t sender_ip,
    unsigned char target_hardware_addr[ETHER_ADDR_LEN])
{
        printf("\nStarting ARP Reply function: Creating the Reply ARP Packet!\n");

        /* Variables */
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

        /* Create the ARP Header */
        printf("Creating ARP Header!\n");
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
        printf("Done Creating ARP Packet!\n");

        /* Create the Ethernet Frame */
        printf("\t Creating Ethernet Frame!\n");
        sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *) arpPacket;
        if (opcode != arp_op_request){
            memcpy(ethernet_header->ether_dhost, target_hardware_addr, ETHER_ADDR_LEN);
        }
        else if (opcode == arp_op_request){
            memset(ethernet_header->ether_dhost, 0xff, ETHER_ADDR_LEN);
        }
        memcpy(ethernet_header->ether_shost, interface2->addr, ETHER_ADDR_LEN);
        ethernet_header->ether_type = htons(ethertype_arp);

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
        size_t ethernetHeaderSize = sizeof(sr_ethernet_hdr_t);
        /* fill in code here */
        /* SANITY CHECK: Minimum Length is valid
           Supposed ethernet frame length defined in sr_pr otocol.h
           This denotes a frame that is insufficient length */
        if (len < ethernetHeaderSize) {
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

        /* Initialize Useful Variables */
        size_t ethernetHeaderSize = sizeof(sr_ethernet_hdr_t);

        /* Sanity Check */
        /* Check the correct length of a ARP packet
         * arpLength = Ethernet Header + Arp Header
         * both values can be found in sr_protocol.h */
        size_t minimum_arpLength = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);

        if (arpLength < minimum_arpLength) {
                fprintf(stderr, "invalid ARP length");
                return -1;
        } printf("ARP Header passed minimum length test!\n");

        /* Construct the arp header from the packet*/
        sr_arp_hdr_t* arp_header = (sr_arp_hdr_t *)(arpPacket + ethernetHeaderSize);

        /* Check if ARP packet is for me.
        If it is, process and reply. Otherwise, discard. */
        struct sr_if *this_interface = sr_get_ip_interface(sr, arp_header->ar_tip);

        /* Check if the arp is a reply or a request */

        /* Reply Case */
        if (arp_header->ar_op != htons(arp_op_request)){
            printf("Received a ARP Reply!\n");
            struct sr_arpreq *request = NULL;

            /* If it is not for our router, we have to cache only if IP is found in our Router's interface's IPs */
            if (!this_interface){
                printf("ARP Reply not for our Router: Check if our router has it's IP!\n");
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
                    printf("Destination IP not found in our Router, terminating...\n");
                    return -1;
                }
            }

            /* If it is for our router, we just cache it */
            if (this_interface){
                printf("ARP Reply for our Router: Caching immediately!\n");
                request = sr_arpcache_insert(&(sr->cache), arp_header->ar_sha, arp_header->ar_sip);
            }

            /* After Caching, need to send it out*/
            struct sr_packet *request_packets = request->packets;
            printf("Sending out cached packets!\n");
            while (request_packets != NULL){
                /* Get the sending interface */
                struct sr_if *sending_interface = sr_get_interface(sr, interface);

                /* Create IP Header */
                sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (request->packets->buf + ethernetHeaderSize);
                ip_header->ip_sum = 0;
                ip_header->ip_sum = htons(cksum(ip_header, ip_header->ip_hl*4));
                ip_header->ip_ttl = ip_header->ip_ttl - 1;

                /* Create Ethernet Header*/
                sr_ethernet_hdr_t * ethernet_header = (sr_ethernet_hdr_t *) request_packets->buf;
                memcpy(ethernet_header->ether_shost, sending_interface->addr, ETHER_ADDR_LEN);
                memcpy(ethernet_header->ether_dhost, arp_header->ar_sha, ETHER_ADDR_LEN);

                /* Send current Packet in while loop*/
                sr_send_packet(sr, request_packets->buf, request_packets->len, interface);
                printf("Request packet sent!\n");

                /* Traverse to next request Packet */
                request_packets = request_packets->next;
            }
            printf("Freeing Memory!\n");
            sr_arpreq_destroy(&(sr->cache), request);
        }

        /* Request Case */
        if (arp_header->ar_op == htons(arp_op_request)){
            printf("Received a ARP Request!\n");

            /* If it is for this router, we need to send a reply */
            if (this_interface){
                printf("\tARP Request is for this router: Send Reply");
                return send_arp(sr, arp_op_reply, arp_header->ar_sip, arp_header->ar_sha);
            }

            /* ARP Request not for this router */
            if (!this_interface){
                printf("\tARP Request destination is not this router!\n");
                return -1;
            }
        }

        return 0; /* Just making sure GCC doesn't complain */
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
        size_t ethernetHeaderSize = sizeof(sr_ethernet_hdr_t);
        size_t ipHeaderSize = sizeof(sr_ip_hdr_t);
        size_t minimum_ipLength = ethernetHeaderSize + ipHeaderSize;

        /* Sanity Check */
        /* Check the correct length of a IP packet
         * ipLength = IP Header + IP Header
         * both values can be found in sr_protocol.h */
        if (ipLength < minimum_ipLength) {
                fprintf(stderr, "invalid IP length!\n");
                return -1;
        } printf("\tIP Header passed minimum length test!\n");

        /* Construct the IP Header from the packet*/
        sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(ipPacket + ethernetHeaderSize);

        /* Sanity Check #2: Verify checksums via cksum() from sr_utils.c */
        uint16_t cksum_result = cksum(ip_header, ip_header->ip_hl);
        if (!cksum_result) {
                fprintf(stderr, "IP Checksum failed!\n");
                return -1;
        } printf("IP Header passed checksum test!\n");

        /* Get the IP interface: Implemented in sr_if.c */
        struct sr_if *destination = sr_get_ip_interface(sr, ntohl(ip_header->ip_dst));

        /* If the packet is for us: We process it */
        if (destination != NULL){
            printf("Packet is for us! \n");
            /* Save the protocol type */
            uint8_t protocol_type = ip_header->ip_p;

            /* If it is an ICMP protocol */
            if (protocol_type == ip_protocol_icmp){
                printf("This IS a ICMP protocol!\n");

                /* Construct the header to check if it is echo request */
                sr_icmp_hdr_t *ICMP_header = (sr_icmp_hdr_t *) (ipPacket + ethernetHeaderSize + ipHeaderSize);

                /* Check the checksum of the ICMP Header */
                uint32_t icmp_checksum = ICMP_header->icmp_sum;
                uint32_t ver_sum = cksum((uint8_t *) ICMP_header, ntohs(ip_header->ip_len) - ipHeaderSize);
                if (icmp_checksum != ver_sum){
                    fprintf(stderr, "ICMP checksum does not match! \n");
                    return -1;
                }

                /* If it is not a echo request, we dont' do anything? */
                if(ICMP_header->icmp_code != 0 || ICMP_header->icmp_code != 8){
                    printf("Not an echo request! Ending!\n");
                    return -1;
                }

                /* If it is a echo request, we send it */
                if(ICMP_header->icmp_code == 0 && ICMP_header->icmp_code == 8){
                    printf("Received an Echo request!\n");
                    /* Send it here */
                    type = 0; code = 0;
                    printf("Sending ICMP Message Type 0\n");
                    return ICMP_Message0(sr, ipPacket, interface, type, code);
                }
            }

            /* If it is not a ICMP protocol */
            else if(protocol_type != ip_protocol_icmp){
                printf("This is not a ICMP Protocol!!! Sending Type 3!\n");
                /* This is either TCP or UDP: Send port unreachable, type 3, code 3 */
                type = 3; code = 3;
                printf("Sending ICMP Message Type 3\n");
                return ICMP_Message3(sr, ipPacket, interface, type, code);
            }
        }

        /* Otherwise, if the packet is not intended for us */
        /* Find out which entry in the routing table has the longest prefix match with the destination IP address. */
        /* Check the ARP cache for the next-hop MAC address corresponding to the next-hop IP. If it’s there, send it.  */
        /* Otherwise, send an ARP request for the next-hop IP (if one hasn’t been sent within the last second), and add the packet to the queue of packets waiting on this ARP request. */
        else if (!destination){
            printf("This packet is not for us! We will just pass it on!\n");
            /* Datagram should be forwarded: Decrement the TTL */

            /* Check if decrementing will result in 0 */
            uint8_t current_TTL = ip_header->ip_ttl;
            if ((current_TTL - 1) <= 0){
                printf("TTL: TIME EXCEEDED! Discarding Packet\n");
                /* Need to send a icmp message with type 11, code 0 */
                type = 11; code = 0;
                printf("Sending ICMP Message Type 11\n");
                return ICMP_Message11(sr, ipPacket, interface, type, code);
            } printf("TTL check OK! \n");

            /* Now that we know we can forward it since TTL allows it */
            /* We need to get a routing table */
            struct sr_rt *currentRoutingTable = sr->routing_table;
            printf("Got routing table!\n");

            /* Traverse through the table and find the correct destination */
            while (currentRoutingTable != NULL){
                /* Destination IP logical AND with a subnetmask == subnet address */
                uint32_t packetDestination = ip_header->ip_dst & currentRoutingTable->mask.s_addr;

                /* Check if it matches a routing table Destination */
                printf("Finding Routing Table Match!\n");
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
                        ip_header->ip_sum = htons(cksum(ip_header, ip_header->ip_hl*4));
                        printf("\t\t\t\tMatch Found: Sending IP Packet !\n");
                        return sr_send_packet(sr, ipPacket, ipLength, currentRoutingTable->interface);
                    }

                    /* If no match found send an ARP request for the next-hop IP ,
                    and add the packet to the queue of packets waiting on this ARP request. */
                    if (arp_match == NULL){
                        printf("Match not Found: Send ARP request for next-hop IP and queue!\n");
                        struct sr_arpreq *queuereq = sr_arpcache_queuereq(&(sr->cache), currentRoutingTable->gw.s_addr,
                        ipPacket, ipLength, interface);

                        /* Check if ARP Request has been sent within last second */
                        double time_difference = difftime(time(NULL), queuereq->sent);
                        uint32_t sent = queuereq->times_sent;
                        if (time_difference > 1){
                            /*  Check if it has been sent 5 times */
                            if (sent > 5){
                                printf("ARP Request has been sent 5 times with no response!\n"
                                "Sending destination host unreachable ICMP to all senders waiting "
                                "for this ARP!\n");
                                /* Send ICMP type 3, code 1 for all packets in the request*/
                                type = 3; code = 1;
                                struct sr_packet *packets = queuereq->packets;
                                while (packets!=NULL){
                                    printf("\t\t\t\t\tSending ICMP Message Type 3!\n");
                                    ICMP_Message3(sr, packets->buf, packets->iface, type, code);
                                    packets = packets->next;
                                } sr_arpreq_destroy( &(sr->cache), queuereq);
                            }
                            if (sent <= 5){
                                printf("Now sending the ARP Request!\n");

                                unsigned char sender_hardware_address[ETHER_ADDR_LEN];
                                memset(sender_hardware_address, 0, ETHER_ADDR_LEN);
                                send_arp(sr, arp_op_request, queuereq->ip, sender_hardware_address);
                                printf("ARP PACKET SENT!!! Need to make changes in the cache..\n");

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
                return ICMP_Message3(sr, ipPacket, interface, type, code);
            }
        }

        return 0; /* Temp: So make gcc doesn't lose it's shit */
}
