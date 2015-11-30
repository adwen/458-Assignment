#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "icmp.h"
#include "ip.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_router.h"
#define DEBUG 1

/*---------------------------------------------------------------------
 FUNCTION: processIP
 - handles all logic from sr_handlepacket related to IP
 *---------------------------------------------------------------------*/
void processIP(struct sr_instance *sr,
		uint8_t *ipPacket/* lent */,
		unsigned int len,
		char *interface/* lent */)
{
	int sanity_check = ipSanityChecks(ipPacket,len);  //TODO: Fix variable name

	uint8_t * ethernetHeader = (uint8_t *) (ipPacket + sizeof(sr_ethernet_hdr_t));
	sr_ip_hdr_t * ipHeader = (sr_ip_hdr_t *)(ipPacket + sizeof(sr_ethernet_hdr_t));
	if (sanity_check == -1){
		return;
	}
	if (sanity_check== -2) {
		ipHeader->ip_ttl--;
		icmpMessage(sr, ethernetHeader, ICMP_TIME_EXCEEDED, ICMP_DEFAULT_CODE);
		return;
	}

	// get the interfaces from sr
	struct sr_if *interfaces = sr->if_list;

	// Go through every interface and check if it mactches one of our interaces
	while (interfaces != NULL) {
		// If one of the interfaces matches our ipHeader destination field
		if (interfaces->ip == ipHeader->ip_dst){
			break;
		}
		interfaces = interfaces->next;
	}

	// Case where we found a matching interface
	if (interfaces != NULL) {
		printf("Found a Matching interface.\n");
		// Remove the ethernet part of the header to isolate the IP
		len = len - sizeof(sr_ethernet_hdr_t);

		// If it is an ICMP packet -> send a ICMP reply
		if (ipHeader->ip_p == ICMP){
			printf("Received a ICMP Packet.\n");

			sr_icmp_hdr_t *icmpHeader = (sr_icmp_hdr_t *)((uint8_t *)ipHeader + sizeof(sr_ip_hdr_t));
			uint16_t icmpChecksum = icmpHeader->icmp_sum;
			icmpHeader->icmp_sum = 0;

			// Verify the checksum is correct
			if (icmpChecksum != cksum(icmpHeader,len - sizeof(sr_ip_hdr_t))){
				printf("Error: ICMP checksum incorrect.\n");
				return;
			}

			// Echo Request = Make a echo Reply
			if (icmpHeader->icmp_type == ICMP_ECHO_REQUEST){
				if (DEBUG) printf("ICMP_ECHO_REQUEST receieved.\n");
				icmpMessage(sr, ethernetHeader, ICMP_ECHO_REPLY, ICMP_DEFAULT_CODE); //send icmp echo reply if we receive a request
			}
		}

		// If it is a TCP or UDP, do prot unreachable
		else if (ipHeader->ip_p == UDP || ipHeader->ip_p == TCP){
			if (DEBUG) printf("We can't deal with TCP OR UDP.\n");
			icmpMessage(sr, ethernetHeader, ICMP_DEST_UNREACHABLE, ICMP_PORT_UNREACHABLE); //send unreachable message if receive a udp or tcp request
		}
	}

	// If we couldnt find a matching interface, we have to consult the routing table
	else {
		printf("Couldn't find matching interface, consulting routing table.\n");
		struct sr_rt *longestPrefixMatch = findLPM(ipHeader->ip_dst, sr->routing_table);
		// Null Implies no LPM found -> Send dest unreachable
		if (longestPrefixMatch == NULL){
			printf("Cant find ip in routing table.\n");
			icmpMessage(sr, ethernetHeader, ICMP_DEST_UNREACHABLE, ICMP_PORT_UNREACHABLE);
	   }
	   // If LPM found
	   else{}
			printf("Longest Prefix Match found in routing table \n");
			ipHeader->ip_ttl--;                                         // Decrement TTL
			ipHeader->ip_sum = 0;                                       // Checksum initalization
			ipHeader->ip_sum = cksum(ipHeader,sizeof(sr_ip_hdr_t));     // Calculate new checksum
			uint32_t packet_size = len;
			uint8_t *newPacket = malloc(packet_size);
			sr_ethernet_hdr_t *newEthernetHeader = (sr_ethernet_hdr_t *) newPacket;
			struct sr_if *destination = sr_get_interface(sr,longestPrefixMatch->interface);
			if (destination==NULL){
			  printf("router interface cannot be found\n.");
			  return;
			}
			memcpy(newEthernetHeader->ether_shost, destination->addr, ETHER_ADDR_LEN);
			newEthernetHeader->ether_type = htons(ETHERTYPE_IP);
			memcpy(newPacket + sizeof(sr_ethernet_hdr_t), ipHeader, (len - sizeof(sr_ethernet_hdr_t)));
			struct sr_arpentry *arpEntry = sr_arpcache_lookup(&sr->cache,longestPrefixMatch->gw.s_addr);
			if (arpEntry == NULL){
				struct sr_arpreq  *newARPRequest = sr_arpcache_queuereq(&sr->cache,longestPrefixMatch->gw.s_addr,
				newPacket, len, longestPrefixMatch->interface);
				handle_arpreq(sr, newARPRequest);
			  }
			else
			{
				memcpy(newEthernetHeader->ether_dhost,arpEntry->mac,ETHER_ADDR_LEN);
				sr_send_packet(sr, newPacket, packet_size, longestPrefixMatch->interface);
			}
			free(newPacket); // Since we called Malloc
	   }
}

/*---------------------------------------------------------------------
 FUNCTION: ipSanityChecks
 - script to perform simple sanity checks on a Ip Packet
 	- TTL Expire Check
	- Invalid header Length
 *---------------------------------------------------------------------*/
int ipSanityChecks(uint8_t * ip_packet,unsigned int len){

	sr_ip_hdr_t *ipHeader = (sr_ip_hdr_t *)( ip_packet + sizeof(sr_ethernet_hdr_t));

	// Check #1 -> TTL Expired
	if (ipHeader->ip_ttl <= 1){
		printf("Error: TTL Expired");
		return -2 ;
	}

	// Check #2 -> Invalid Length
	if (sizeof(sr_ip_hdr_t) > len){
		printf("Error: Invalid IP length\n");
		return -1;
	}

	// Check #3 Checksums
	uint16_t currentChecksum = ipHeader->ip_sum;
	ipHeader->ip_sum = 0x0000;
	uint16_t matchingChecksum = cksum(ipHeader, sizeof(sr_ip_hdr_t));
	if (currentChecksum != matchingChecksum){
		printf("Error: Checksums do not match\n");
		return -1;
	}

	return 0;
}
