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

        /* fill in code here */
        /*sr_ethernet_hdr_t* header = (sr_ethernet_hdr_t*) packet; */

        /* SANITY CHECK: Minimum Length is valid
           Supposed ethernet frame length defined in sr_protocol.h
           This denotes a frame that is insufficient length */
        if (len < sizeof(sr_ethernet_hdr_t)) {
                fprintf(stderr, "Packet failed Sanity Check #1: ");
                return;
        } printf("Passed initial length test => Valid Ethernet Frame!\n");

        /* Case where we receive a ARP */
        if (ethertype(packet) == ethertype_arp) {

                printf("Packet is a ARP!\n");
                /* Pass all the parameters to the ARP function */
                process_ARP(sr, packet, len, interface);
        }

        /* Case where we receive a IP */
        else if (ethertype(packet) == ethertype_ip) {
                printf("Packet is a IP packet!\n");
                process_IP(sr, packet, len, interface);
                /* sr_send_packet(sr, packet, len, interface); */
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

        return 0; /* Temp: So make gcc doesn't lose it's shit */


}

/* Function to process the logic behind the IP Packet */
int process_IP(struct sr_instance* sr,
               uint8_t * ipPacket /* lent */,
               unsigned int ipLength,
               char* interface /* lent */)
{
        printf("Entered IP packet processing block \n");
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

        /* Sanity Check #2: Verify checksums via cksum() from sr_utils.c */
        uint16_t cksum_result = cksum(ip_header, ntohl(ip_header->ip_hl));
        if (!cksum_result) {
                fprintf(stderr, "Checksum failed!\n");
                return -1;
        } printf("IP Header passed checksum test!\n");

        /* Check the destination */
        struct sr_if *destination = sr_get_ip_interface(sr, ntohl(ip_header->ip_dst));

        /* If the packet is for us: We process it */
        if (destination){
            printf("Packet  is for us! \n");

            /* Check the protocol type */
            uint8_t protocol_type = ip_header->ip_p;

            /* If it is an ICMP protocol */
            if (protocol_type == ip_protocol_icmp){
                printf("This IS a ICMP protocol");

                /* Construct the header **/
                sr_icmp_hdr_t *ICMP_header = (sr_icmp_hdr_t *) (ethernetHeaderSize + ipHeaderSize + ipPacket);

                /* If it is not a echo request, we dont' do anything? */
                if(ICMP_header->icmp_code! = 0 || ICMP_header->icmp_code!= 8){
                    printf("Not an echo request!\n");
                    return -1;
                }


                /* If it is a echo request, we send it */
                if(ICMP_header->icmp_code! = 0 || ICMP_header->icmp_code! = 8){
                    printf("Echo request")
                    /* Send it here */
                }
            }

            /* If it is not a ICMP protocol */
            else if(protocol_type != ip_protocol_icmp){
                printf("This is not a ICMP Protocol!!!");
                /* Do some sending response */
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
                int type = 11; int code = 0;
            } printf("TTL check OK! \n");

        }

        return 0; /* Temp: So make gcc doesn't lose it's shit */
}
