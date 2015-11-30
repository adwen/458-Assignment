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
 FUNCTION: constructHeaderIP
 - Constructs a ipHeader and updates its field according to a previous ipHeader
 *---------------------------------------------------------------------*/
 void constructHeaderIP(sr_ip_hdr_t *ipHeader, sr_ip_hdr_t *previous, uint32_t newLength, uint32_t newDestination,
     struct sr_if *interface, uint8_t icmpType, uint8_t code)
 {
     ipHeader->ip_hl = previous->ip_hl;
     ipHeader->ip_v = previous->ip_v;
     ipHeader->ip_tos = previous->ip_tos;
     ipHeader->ip_len = htons(newLength - sizeof(sr_ethernet_hdr_t));
     ipHeader->ip_id = 0;
     ipHeader->ip_off = htons (IP_DF | 0);
     ipHeader->ip_ttl = INIT_TTL;
     ipHeader->ip_p = ICMP;
     ipHeader->ip_dst = newDestination;

     // If it is the valid ICMP Type
     if (icmpType == ICMP_ECHO_REPLY || (code == ICMP_PORT_UNREACHABLE && icmpType == ICMP_DEST_UNREACHABLE)){
         ipHeader->ip_src = previous->ip_dst;
     }
     else {
         ipHeader->ip_src = interface->ip;
     }

     ipHeader->ip_sum = 0;
     ipHeader->ip_sum = cksum(ipHeader, sizeof(sr_ip_hdr_t));
 }

 /*---------------------------------------------------------------------
  FUNCTION: constructType3
  - constructs a ICMP Type 3 header and fills its fields
  *---------------------------------------------------------------------*/
 void constructType3(sr_icmp_t3_hdr_t *Type3, uint8_t type, uint8_t code, sr_ip_hdr_t *previous){
     Type3->icmp_type = type;
     Type3->icmp_code = code;
     Type3->icmp_sum = 0;
     Type3->unused = 0;
     Type3->next_mtu = 0;
     memcpy(Type3->data, previous, ICMP_SIZE);
     Type3->icmp_sum = cksum(Type3, sizeof(sr_icmp_t3_hdr_t));
 }

 /*---------------------------------------------------------------------
  FUNCTION: processIP
  - Constructs a ICMP Echo Reply header and fills it's fields
  *---------------------------------------------------------------------*/
 void constructHeaderEcho(sr_icmp_hdr_t *icmpHeader, uint32_t newLength, uint8_t type, uint8_t code, sr_ip_hdr_t *previous){
     icmpHeader->icmp_type = type;
     icmpHeader->icmp_code = code;
     memcpy((uint8_t *)icmpHeader + sizeof(sr_icmp_hdr_t), (uint8_t *)previous + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t), newLength - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t) - sizeof(sr_icmp_hdr_t));
     icmpHeader->icmp_sum = 0;
     icmpHeader->icmp_sum = cksum(icmpHeader, newLength - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
 }

 /*---------------------------------------------------------------------
  FUNCTION: icmpMessage
  - handles all logic to send a icmpMessage
  *---------------------------------------------------------------------*/
 void icmpMessage(struct sr_instance *sr, uint8_t *packet, uint8_t type, uint8_t code) {
     uint32_t newLength;
     sr_ip_hdr_t *previous = (sr_ip_hdr_t *) packet;

     if (type == ICMP_ECHO_REPLY){
         newLength = sizeof(sr_ethernet_hdr_t) + ntohs(previous -> ip_len);
     }
     else if (type == ICMP_TIME_EXCEEDED || type == ICMP_DEST_UNREACHABLE){
         newLength = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
         printf("Time Exceeded or Destination unreachable\n");
     }
     uint32_t newDestination = previous -> ip_src;

     // Find the LPM destination
     struct sr_rt *LPM = findLPM(newDestination, (struct sr_rt*)sr -> routing_table);
     if (LPM == NULL){
         printf("No matches found in routing table. Terminating...\n");
         return;
     }

     // If LPM is found, get its destination interface
     struct sr_if *interface = sr_get_interface(sr, LPM->interface);

     // Construct the Ethernet header of the new Packet
     uint8_t *newPacket = (uint8_t *) malloc(newLength);
     sr_ethernet_hdr_t *ethernetHeader = (sr_ethernet_hdr_t *)newPacket;
     memcpy (ethernetHeader->ether_shost, interface ->addr, ETHER_ADDR_LEN);
     struct sr_arpentry *arpEntry = sr_arpcache_lookup(&sr->cache, LPM->gw.s_addr);
     if(arpEntry == NULL){
         memset(ethernetHeader->ether_dhost, '\0', ETHER_ADDR_LEN);
     }
     else{
         if (DEBUG) printf("ArpEntry Not Null\n");
         memcpy(ethernetHeader->ether_dhost, arpEntry->mac, ETHER_ADDR_LEN);
     }
     ethernetHeader->ether_type= htons(ETHERTYPE_IP);

     // Construct the IP Header of the new Packet
     sr_ip_hdr_t *ipHeader = (sr_ip_hdr_t *)(newPacket + sizeof(sr_ethernet_hdr_t));
     constructHeaderIP(ipHeader, previous, newLength, newDestination, interface, type, code);

     // Create a normal ICMP Header
     sr_icmp_hdr_t *icmpHeader = (sr_icmp_hdr_t *) ((uint8_t *) ipHeader + sizeof(sr_ip_hdr_t));

     // Create a Type 3 Header
     sr_icmp_t3_hdr_t *icmpT3Hdr = (sr_icmp_t3_hdr_t *)icmpHeader;

     if(type == ICMP_ECHO_REPLY) {
         constructHeaderEcho(icmpHeader, newLength, type, code, previous);
     }

     else if (type == ICMP_TIME_EXCEEDED || type == ICMP_DEST_UNREACHABLE) {
         constructType3(icmpT3Hdr, type, code, previous);
     }

     // If arpEntry was not null = send the packet
     if (arpEntry){
         sr_send_packet (sr, newPacket, newLength, LPM->interface);
     }

     else {
         // Get the next hop mac address from queue
         struct sr_arpreq *arpRequest = sr_arpcache_queuereq (&sr->cache, LPM->gw.s_addr, newPacket, newLength, LPM->interface);
         handle_arpreq(sr, arpRequest);
     }

     free(newPacket);
 }
