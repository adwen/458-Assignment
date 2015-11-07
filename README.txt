Team:
	- Julian Chow (g3chowju)
	- Toumy Yan (g2yantou)
	- Yu Ching Chen (g3yuch)

Our team made the design decision to make helper functions to simplify the complexity of the code.
As a very brief overview, sr_handlepacket delegates the task of processing the logic of 
receiving an IP Packet and ARP Packet to helper functions process_IP and process_ARP which 
takes all the arguments from sr_handlepacket.

file: sr_router.c

	core function: sr_handlepacket
		Upon receiving an ethernet frame, our sr_handlepacket function instantly does a quick sanity check for a valid
		ethernet frame length.
		It also checks whether or not the received frame is in the correct format as we don't support 
		any processing of packet types other than IP and ARP. Should these 2 checks fail it simply returns 
		error messages and does no further processing (equivalent to dropping the packet).
		In the (common) case that these 2 checks pass,  sr_handlepacket forwards 
		the parameters to the ARP and IP handling Functions.
		
	main function: process_IP
		This function is invoked only from sr_handlepacket and is used to handle the logic of a incoming IP Packet.
		process_IP first does a sanity check for the length of an IP Header and it's checksum 
		(an error is returned if either fails).
		The function then uses another helper function (sr_get_ip_interface) to get the 
		destination of the incoming ip header.
			* This function is mostly a copy & paste of sr_get_interface defined sr_if.c, 
			  we only modified it to deal with ip_destination instead of a name character
			  
		If process_IP detects that our current router isn't the intended destination, 
		it does a quick check to verify if the TTL will expire . (if it does, it stops what its doing and 
		sends an ICMP Type 11 message). process_IP then looks at the current router's routing table
		to see if we hold a entry for this IP's destination using Longest Prefix Match.
			- if no Longest Prefix match can be found we pass it into function handle_arpreq
			- if a Longest Prefix match is found, we decrement the TTL and update the checksum before 
			  we sent the packet
			* if we go through every entry in the router's routing table without finding anything, 
			  it sends a ICMP Type 3 (Host Unreachable)
		
		If process_IP detects that our current router is the actual intended destination, 
		it checks if the incoming packet is a echo request (ICMP Type 8, Code 0) while 
		ignoring everything else. It then sends an Echo reply (ICMP Type 0, Code 0)
		
		
	main function: process_ARP
		Similarily to process_IP, this function starts with simple sanity checks (terminate if they don't pass) 
		and gets the intended interface from the incoming packet. 
			For an ARP Reply:
				- If this router is not the destination interface, the function only caches the ARP Reply 
				if the destination is in our interfaces
				IP Addresses (If there is no match, it does not do anything more with the packet)
				- If this router is the destination interface it simply caches it unconditionally and proceeds
				- It then broadcasts to everybody waiting for on this ARP Request
			For an ARP Reply:
				- It does nothing more with the packet if this router is not the intended destination
				- If this router is the destination interface, we response with a ARP Message via ARP_Message
				
	send function: ARP_Message
		This function is called by handle_arpreq and process_ARP only.
		This function simply creates the ARP packet (process differs depending on reply / request) 
		and sends it to a specified destination
			
	send functions: ICMP_Message0, ICMP_Message3, ICMP_Message11
		This function simply sends a Type of ICMP message with code as a parameter.
		The structs that make up the headers are defined in sr_protocol.h and is modeled after
		the information provided from: http://www.networksorcery.com/enp/protocol/
		To Construct the ICMP header for each type:
			- Because a Type 0 (Echo Reply) is only sent upon receiving a Type 8 ICMP Packet (Echo Request)
			  The Type 0 takes the code from the parameter, the identifier from the incoming packet but 
			  rips the sequence number, identifier and timestamp from the incoming ICMP Packet
			- A Type 3 and Type 11 only utilizes the type and data parameter and computes the checksum afterwards
			  as it is not guaranteed to be a response to a ICMP Packet

file: sr_arpcache.c

	helper function: handle_arpreq
		This function was implemented via the pseudocode instruction detailed at the top of sr_arpcache.h.
		This function handles an incoming ARP Request and is called by process_IP 
		(when we can't find a Longest Prefix Match)
		We used the <time.h> library to determine whether or not the ARP has been sent in the last second or not.
			- If it hasnt been sent in the last second, we grab a pointer to an array that holds packets 
			  for all senders waiting on this ARP and sends a ICMP Type 3 to them.
			- Otherwise, we send an ARP Request accordingly and update the last 
			  time sent and number of times sent in the cache

	helper function: get_charpointer_interface
		Given an IP address, goes through the routing table to get the name of the interface that
		corresponds to this IP address.
	
	main function: sr_arpcache_sweepreqs
		Goes through the linked list of queued ARP requests and determines whether or not the request
		should be resent or scrapped while following specs given out on course webpage.
	
