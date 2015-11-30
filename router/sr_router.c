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
#include <stdlib.h>
#include <string.h>

#include "icmp.h"
#include "arp.h"
#include "ip.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#define DEBUG 1
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
         uint8_t * packet/* lent */,
         unsigned int len,
         char* interface/* lent */)
 {
     /* REQUIRES */
     assert(sr);
     assert(packet);
     assert(interface);
     printf ("Received packet of length length: %u\n",len);
     if (len < sizeof(sr_ethernet_hdr_t)){
         printf("Invalid Frame Size\n");
         return;
     }

     uint16_t packetType = ntohs(((sr_ethernet_hdr_t *)packet)->ether_type);
     printf("*** -> Received packet of length %d  and of type: %d\n", len, packetType);
     if (packetType == ETHERTYPE_IP){
         printf("Received an IP packet!\n");
         processIP(sr, packet, len, interface);
     }

     else if (packetType == ETHERTYPE_ARP)
     {
         printf("Received an ARP packet!\n");
         processARP(sr, packet, len, interface);
     }
 }



/*---------------------------------------------------------------------
 * struct sr_rt *findLPM(uint32_t ip_dest, struct sr_rt * rt)
 * Scope:  Global
 *
 * Does a bitwise AND of the ip_destination and subnet mask
 * and tries to locate it in our current routing table based on
 * longest prefix matching.  Returns a the sr_table entry associated
 * with the ip destination, or if not found, returns NULL
 *---------------------------------------------------------------------*/
 struct sr_rt *findLPM(uint32_t destinationIP, struct sr_rt *rt)
 {
     printf("Computing Longest Prefix Match!\n");

     struct sr_rt *currentPrefix = rt;
     struct sr_rt *LPM = NULL;
     // Traverse
     while (currentPrefix != NULL){
         if ((currentPrefix->dest.s_addr & currentPrefix->mask.s_addr) == (destinationIP & currentPrefix->mask.s_addr)){

             if (LPM == NULL){
                 LPM = currentPrefix;
             }
             else if (currentPrefix->mask.s_addr > LPM->mask.s_addr){
                 LPM = currentPrefix;
             }
         }
         // Got to next entry
         currentPrefix = currentPrefix->next;
     }
     if (LPM == NULL){
         printf("Error: No Longest Prefix Match Found!\n");
     }
     return LPM;
 }
