#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

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
 *
 *                         ARP FUNCTIONS
 *
 *---------------------------------------------------------------------*/

/*---------------------------------------------------------------------
 * Method: void sr_handle_arp_packet(struct sr_instance* sr,
             uint8_t * arp_packet,
             unsigned int len,
             char* interface)
 * Scope: Global
 *
 * This method determines if ARP packet is request or reply and
 * processes accordingly.
 *---------------------------------------------------------------------*/

 void processARP(struct sr_instance *sr,
                 uint8_t *arp_packet,
                 unsigned int len,
                 char *interface)
 {
     sr_arp_hdr_t *arpHeader = (sr_arp_hdr_t *)(arp_packet + sizeof(sr_ethernet_hdr_t));

     // If the ARP Packet is a ARP_REQUEST
     if (ntohs(arpHeader->ar_op) == ARP_REQUEST) {
         struct sr_if *interfaces = sr->if_list;
         while (interfaces != NULL)
         {
             // If a match destination interface match is found
             if (interfaces->ip == arpHeader->ar_tip){
                 break;
             }
             interfaces = interfaces->next;
         }

         // Case where we found a matching interface: interfaces != null
         if (interfaces) {
             // Construct a ARP Reply
             uint8_t *ARPReply = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));

             // Construct the Ethernet Header
             sr_ethernet_hdr_t *ethernetHeader = (sr_ethernet_hdr_t *) ARPReply;
             memcpy(ethernetHeader->ether_dhost, arpHeader->ar_sha, ETHER_ADDR_LEN);
             memcpy(ethernetHeader->ether_shost, interfaces->addr, ETHER_ADDR_LEN);
             ethernetHeader->ether_type = htons(ETHERTYPE_ARP);

             // Construct the ARP Header
             sr_arp_hdr_t *newARP = (sr_arp_hdr_t *)(ARPReply + sizeof(sr_ethernet_hdr_t));
             // Copy some values
             newARP->ar_hrd = htons(ARP_HRD_ETHER);
             newARP->ar_pro = arpHeader->ar_pro;
             newARP->ar_hln = arpHeader->ar_hln;
             newARP->ar_pln = arpHeader->ar_pln;
             newARP->ar_op = htons(ARP_REPLY);
             memcpy(newARP->ar_sha, interfaces->addr, ETHER_ADDR_LEN);
             newARP->ar_sip = arpHeader->ar_tip;
             memcpy(newARP->ar_tha, arpHeader->ar_sha, ETHER_ADDR_LEN);
             newARP->ar_tip = arpHeader->ar_sip;

             // Send reply
             sr_send_packet(sr, ARPReply, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface);
             free(ARPReply);
         }
     }

     // If the ARP Packet is a ARP_REPLY
     else if (ntohs(arpHeader->ar_op) == ARP_REPLY) {
         // Cache it instantly
         struct sr_arpreq *ARPRequest = sr_arpcache_insert(&sr->cache, arpHeader->ar_sha, arpHeader->ar_sip);

         if (ARPRequest != NULL) {
             struct sr_packet *waitingPackets = ARPRequest->packets;
             // Send a reply to all waitingPackets waiting for this
             while (waitingPackets != NULL) {
                 sr_ethernet_hdr_t *ethernetHeader = (sr_ethernet_hdr_t *)(waitingPackets->buf);
                 memcpy(ethernetHeader->ether_dhost, arpHeader->ar_sha, ETHER_ADDR_LEN);
                 sr_send_packet(sr, waitingPackets->buf, waitingPackets->len, waitingPackets->iface);
                 waitingPackets = waitingPackets->next;
             }
             sr_arpreq_destroy(&sr->cache, ARPRequest);
         }
     }
 }


/*---------------------------------------------------------------------
 * Method: void sendARPRequest(struct sr_instance *sr, struct sr_arpreq *req)
 * Scope: Global
 *
 * This method is called to create an Ethernet frame to send an ARP request.
 *---------------------------------------------------------------------*/

 void sendARPRequest(struct sr_instance *sr, struct sr_arpreq *request){

     // Construct the request
     uint8_t *requestPacket = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));

     // Construct the ethernet header
     struct sr_if *interface = sr_get_interface(sr, request->packets->iface);
     sr_ethernet_hdr_t *ethernetHeader = (sr_ethernet_hdr_t *) requestPacket;
     memset(ethernetHeader->ether_dhost, 255, ETHER_ADDR_LEN);
     memcpy(ethernetHeader->ether_shost, interface->addr, ETHER_ADDR_LEN);
     ethernetHeader->ether_type = htons(ETHERTYPE_ARP);

     // Construct the ARP Header
     sr_arp_hdr_t *arpHeader = (sr_arp_hdr_t *)(requestPacket + sizeof(sr_ethernet_hdr_t));
     arpHeader->ar_hrd = htons(ARP_HRD_ETHER);
     arpHeader->ar_pro = htons(ARP_PRO_ETHER);
     arpHeader->ar_hln = ETHER_ADDR_LEN;
     arpHeader->ar_pln = sizeof(uint32_t);
     arpHeader->ar_op = htons(ARP_REQUEST);
     memcpy(arpHeader->ar_sha, interface->addr, ETHER_ADDR_LEN);
     arpHeader->ar_sip = interface->ip;
     memset(arpHeader->ar_tha, 255, ETHER_ADDR_LEN);
     arpHeader->ar_tip = request->ip;

     // Send request
     sr_send_packet(sr, requestPacket, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), request->packets->iface);
     free(requestPacket);
 }
