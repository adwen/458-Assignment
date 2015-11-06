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

 	/* We must calculate the ICMP length first before
 	 * we can caculate the checksum for IP header
 	 */
 	ihdr->ip_len = htons(20 + icmp_hdr_size);
 	ihdr->ip_sum = cksum(packet_new + sizeof(sr_ethernet_hdr_t), ihdr->ip_hl * 4);

 	Debug("*** Sending an ICMP packet ***\n");
 	/*print_hdr_icmp(packet_new + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));*/

 	/* send now */
 	int result = sr_send_packet(sr, packet_new, len_new, interface);
 	free(packet_new);

 	return result;
 }


 int ARP_Message(struct sr_instance* sr, unsigned short ar_op, unsigned char ar_tha[ETHER_ADDR_LEN], uint32_t ar_tip) {
 	unsigned int len_new = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
 	uint8_t *packet_new = (uint8_t *)malloc(len_new);
 	bzero(packet_new, len_new);
 	char *interface = sr_get_charpointer_interface(sr, ar_tip);
 	struct sr_if *if_st = sr_get_interface(sr, interface);

 	/* ethernet frame */
 	sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *) packet_new;
 	if (ar_op == arp_op_request)
 		memset(ehdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
 	else
 		memcpy(ehdr->ether_dhost, ar_tha, ETHER_ADDR_LEN);

 	memcpy(ehdr->ether_shost, if_st->addr, ETHER_ADDR_LEN);
 	ehdr->ether_type = htons(ethertype_arp);

 	/* arp header */
 	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) (packet_new + sizeof(sr_ethernet_hdr_t));
 	arp_hdr->ar_hln = ETHER_ADDR_LEN;
 	arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
 	arp_hdr->ar_op = htons(ar_op);
 	arp_hdr->ar_pln = 4;
 	arp_hdr->ar_pro = htons(ethertype_ip);
 	memcpy(arp_hdr->ar_sha, if_st->addr, ETHER_ADDR_LEN);
 	arp_hdr->ar_sip = if_st->ip;
 	memcpy(arp_hdr->ar_tha, ar_tha, ETHER_ADDR_LEN);
 	arp_hdr->ar_tip = ar_tip;

 	Debug("*** Sending an ARP packet ***\n");
 	/*print_hdrs(packet_new, len_new); */

 	int result = sr_send_packet(sr, packet_new, len_new, interface);
 	free(packet_new);
 	return result;
 }


 struct sr_if* sr_get_interface_from_ip(struct sr_instance *sr, uint32_t ip_dest) {
 	struct sr_if *ifs = sr->if_list;
 	while (ifs) {
 		if (ip_dest == ifs->ip) {
 			return ifs;
 		}
 		ifs = ifs->next;
 	}
     printf("IP %d not found in interface cache!\n", ip_dest);

 	return NULL;
 }

 int process_ARP(struct sr_instance* sr, uint8_t *packet, unsigned int len, char* interface) {

         size_t ethernetHeaderSize = sizeof(sr_ethernet_hdr_t);
         size_t arpHeaderSize = sizeof(sr_arp_hdr_t);

         if (len < ethernetHeaderSize + arpHeaderSize) {
                 fprintf(stderr, "Invalid ARP header size");
                 return -1;
         }

         sr_arp_hdr_t *arpHeader = (sr_arp_hdr_t *)(packet + ethernetHeaderSize);

         if (arpHeader->ar_hrd != htons(arp_hrd_ethernet)) {
                 fprintf(stderr, "ARP hardware format not supported");
                 return -1;
         }

         if (arpHeader->ar_pro != htons(ethertype_ip)) {
                 fprintf(stderr, "ARP header not valid: IPv4 only");
                 return -1;
         }

         struct sr_if *thisInterface = sr_get_ip_interface(sr, arpHeader->ar_tip);
         /* Reply or request? */

         if (arpHeader->ar_op == htons(arp_op_reply)) { /* reply */
                 /* Only cache if the target IP is one of our router's interfaces' IP address */
                 Debug("Receive ARP reply at interface %s\n", interface);
                 struct sr_arpreq *req = NULL;
                 if(thisInterface != NULL) { /* Target is our router */
                         req = sr_arpcache_insert(&(sr->cache), arpHeader->ar_sha, arpHeader->ar_sip);
                 }
                 else if(thisInterface == NULL){
                         req = sr->cache.requests;
                         while (req) {
                                 if (req->ip != arpHeader->ar_sip)
                                         req = req->next;
                         }
                         if (!req) {
                                 fprintf(stderr, "We don't have anything to do with this ARP reply.");
                                 return -1;
                         }
                 }

                 struct sr_packet *pk_st = req->packets;
                 while (pk_st) {
                         sr_ethernet_hdr_t *ehdr_pk = (sr_ethernet_hdr_t *) pk_st->buf;
                         struct sr_if *sending_if = sr_get_interface(sr, interface);
                         memcpy(ehdr_pk->ether_dhost, arpHeader->ar_sha, ETHER_ADDR_LEN);
                         memcpy(ehdr_pk->ether_shost, sending_if->addr, ETHER_ADDR_LEN);
                         sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (pk_st->buf + ethernetHeaderSize);
                         ip_hdr->ip_sum = 0;
                         ip_hdr->ip_ttl -= 1;
                         ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl*4);
                         sr_send_packet(sr, pk_st->buf, pk_st->len, interface);
                         pk_st = pk_st->next;
                 }

                 sr_arpreq_destroy(&(sr->cache), req);
         }

         if (arpHeader->ar_op == htons(arp_op_request)) { /* request */
                 if (!thisInterface) {
                         Debug("ARP request NOT for our router\n");
                         return -1;
                 } else {
                         Debug("ARP request for our router. Sending a reply...\n");
                         return ARP_Message(sr, arp_op_reply, arpHeader->ar_sha, arpHeader->ar_sip);
                 }
         }

         return 0;
 }

 int process_IP(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {
 	/* verify length */
 	int minlen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
 	if (len < minlen) {
 		fprintf(stderr, "Invalid IP header size");
 		return -1;
 	}
 	sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *) packet;
 	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

 	/* verify checksum */
 	if(!cksum(ip_hdr, ip_hdr->ip_hl)) {
 		fprintf(stderr, "Invalid IP header checksum");
 		return -1;
 	}

 	struct sr_if *target_if = sr_get_ip_interface(sr, ip_hdr->ip_dst);

 	if (!target_if) { /* not for us, forward it */
 		if(ip_hdr->ip_ttl <= 1) {
 			/* create a new ICMP type 11 message - time exceeded */
 			Debug("TTL Expired\n");
 			return ICMP_Message(sr, packet, interface, 11, 0);
 		}

 		printf("The Ip packet is not for us. Forwarding...\n");
 		struct sr_rt *rt_node = sr->routing_table;
 		while(rt_node) {
 			if ((ip_hdr->ip_dst & rt_node->mask.s_addr) == rt_node->dest.s_addr) {
 				struct sr_if *out_if = sr_get_interface(sr, rt_node->interface);
 				memcpy(ehdr->ether_shost, out_if->addr, ETHER_ADDR_LEN);

 				/* Searching the destination MAC address through ARP cache */
 				struct sr_arpentry *arp_e = sr_arpcache_lookup(&(sr->cache), rt_node->gw.s_addr);
 				if (arp_e) {
 					memcpy(ehdr->ether_dhost, arp_e->mac, ETHER_ADDR_LEN);
 					free(arp_e);
 					ip_hdr->ip_ttl -= 1;
 					ip_hdr->ip_sum = 0;
 					ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl*4);
 					return sr_send_packet(sr, packet, len, rt_node->interface);
 				} else {
 					handle_arpreq(sr, sr_arpcache_queuereq(&(sr->cache), rt_node->gw.s_addr, packet, len, interface));
 					return 0;
 				}
 			}
 			rt_node = rt_node->next;
 		}

 		/* Destination host unreachable */
 		Debug("Host unreachable\n");
 		return ICMP_Message(sr, packet, interface, 3, 1);

 	} else { /* handle it */
 		printf("The IP packet is for us\n");
 		if (ip_hdr->ip_p != ip_protocol_icmp) {
 			Debug("Not ICMP protocol");
 			return ICMP_Message(sr, packet, interface, 3, 3); /* port unreachable */
 		} else {
 			/* Ignore if it's not an echo request */
 			sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
 			if (icmp_hdr->icmp_type == 8 && icmp_hdr->icmp_code == 0) {
 				Debug("Receive an ICMP Echo request\n");
 				return ICMP_Message(sr, packet, interface, 0, 0);
 			}
 			else
 				return 0;
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
         uint8_t * packet/* lent */,
         unsigned int len,
         char* interface/* lent */)
 {
   /* REQUIRES */
   assert(sr);
   assert(packet);
   assert(interface);

   printf("*** -> Received packet of length %d \n",len);

   /* Check packet type */
   uint16_t ethtype = ethertype(packet);
   unsigned int minlen = sizeof(sr_ethernet_hdr_t);

   if (len < minlen) {
 	  fprintf(stderr, "Invalid Ethernet frame size");
 	  return;
   }

   switch(ethtype) {
   	  case ethertype_arp:
   		 Debug("Receive an ARP packet sent to interface %s\n", interface);
   		 process_ARP(sr, packet , len, interface);
   		 break;

   	  case ethertype_ip:
   		  Debug("Get an IP header sent to interface: %s\n", interface);
   		  process_IP(sr, packet, len, interface);
   		  break;

   	  default:
   		  fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
   		  break;
   }


 }/* end sr_ForwardPacket */
