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


#include "ip.h"
#include "arp.h"
#include "icmp.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
//#include "sr_nat.h"
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
    /*if (sr->nat_enabled) {
        sr_nat_init(&(sr->nat));
    }*/
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

    printf("*** -> Received packet of length %d \n",len);

    /* Sanity Check: Check if length matches */
    if (len < sizeof(sr_ethernet_hdr_t)) {
        printf("Ethernet Header insufficient length... Terminating\n");
        return;
    }

    // Build the ethernetHeader from the received packet
    sr_ethernet_hdr_t *ethernetHeader = (sr_ethernet_hdr_t *) packet;

    // Check and store Packet Type
    uint16_t packetType = ntohs(ethernetHeader->ether_type);

    // Get the interface we received it from
    struct sr_if *receivedInterface = sr_get_interface(sr, interface);

    switch (packetType){

        case IP_PACKET:
            processIP(sr, packet, len, receivedInterface);
            break;

        case ARP_PACKET:
            processARP(sr, packet, len, receivedInterface);
            break;
    }

} /* -- sr_handlepacket -- */


void sendToInterface(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *sendingInterface, uint32_t ip){
    //assert(sr);
    //assert(packet);
    //assert(sendingInterface);

    struct sr_arpentry *arpEntry = sr_arpcache_lookup(&(sr->cache), ip);

  	/* If the packet is not found in the ARP cache, pass to handle_arpreq */
    if (!arpEntry) {
        struct sr_arpreq *arpRequestPointer = sr_arpcache_queuereq(&(sr->cache), ip, packet, len, sendingInterface->name);
        handle_arpreq(sr, arpRequestPointer);
    }

  	/* if Packet is found in the ARP cache: simply send it out*/
    if (arpEntry) {
        sr_ethernet_hdr_t *ethernetHeader = (sr_ethernet_hdr_t *)packet;

        memcpy(ethernetHeader->ether_dhost, arpEntry->mac, ETHER_ADDR_LEN);
        memcpy(ethernetHeader->ether_shost, sendingInterface->addr, ETHER_ADDR_LEN);

        sr_send_packet(sr, packet, len, sendingInterface->name);
        free(arpEntry);
    }
}
