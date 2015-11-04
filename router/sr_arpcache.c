#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_rt.h"
#include <arpa/inet.h>


char* sr_get_charpointer_interface(struct sr_instance* sr, uint32_t ip)
{
    struct sr_rt* rt_node = sr->routing_table;
    while (rt_node) {
        if ((ip & rt_node->mask.s_addr) == rt_node->dest.s_addr) {
            return rt_node->interface;
        }
        rt_node = rt_node->next;
    }

    return NULL;
}

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* Fill this in */
    struct sr_arpcache *cache = &(sr->cache);
    struct sr_arpreq *req = cache->requests;
    struct sr_arpreq *nextreq = NULL;

    /* Traverse linked list of arp requests */
    while (req != 0)
    {
        nextreq = req->next;
        time_t req_time = req->sent;
        time_t current_time = time(NULL); /* get current time */
        uint32_t req_num_sent = req->times_sent;
        char* interface = sr_get_charpointer_interface(sr, req->ip);
        struct sr_if* this_interface = sr_get_interface(sr, interface);

        if (current_time < 0)
        {
            fprintf(stderr, "Can't get current time!\n" );
            return;
        }

        /* If it hasnt been sent in the past second, send a new arp request. */
        if ((current_time - req_time) > 1.0)
        {            
            sr_ethernet_hdr_t new_eth_hdr;
            sr_arp_hdr_t new_arp_hdr;
            /* Setup the ethernet header struct */

            /* all arp requests go to 0xff */
            memset(new_eth_hdr.ether_dhost, 0xff, ETHER_ADDR_LEN);
            memcpy(new_eth_hdr.ether_shost, this_interface->addr, ETHER_ADDR_LEN);
            new_eth_hdr.ether_type = htons(ethertype_arp);

            /* Setup the arp header struct */
            new_arp_hdr.ar_hrd = htons(arp_hrd_ethernet);
            new_arp_hdr.ar_pro = htons(ethertype_ip);
            new_arp_hdr.ar_hln = ETHER_ADDR_LEN;
            new_arp_hdr.ar_pln = 4; /* ??? */
            new_arp_hdr.ar_op = htons(arp_op_request);
            memcpy(&(new_arp_hdr.ar_sha), this_interface->addr, ETHER_ADDR_LEN);
            new_arp_hdr.ar_sip = htonl(this_interface->ip);
            /* Hardware address of target arp request is 0 */
            memset(&(new_arp_hdr.ar_tha), 0, ETHER_ADDR_LEN);
            new_arp_hdr.ar_tip = htonl(req->ip);

            /* Use a buffer as temp storage for the new packet */
            int buffersize = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
            uint8_t* buffer = malloc(buffersize);

            /* Put the contents of both structs into the packet buffer */
            memcpy(buffer, &new_eth_hdr, sizeof(sr_ethernet_hdr_t));
            memcpy(buffer + sizeof(sr_ethernet_hdr_t), &new_arp_hdr, sizeof(sr_arp_hdr_t));

            sr_send_packet(sr, buffer, buffersize, interface);

            pthread_mutex_lock(&(cache->lock));
            req->sent = current_time;
            req->times_sent++;
            pthread_mutex_unlock(&(cache->lock));
            free(buffer);
        }

        /* 5 times with no response, send destination host unreachable and destroy request */
        else if (req_num_sent >= 5)
        {
            /* Somehow notify all packets waiting that this host is unreachable */
            struct sr_packet* packet = req->packets;
            /* Iterate over the linked list of packets that depend on this */
            while (packet != 0)
            {
                /* Send ICMP type 3 notification */
                ICMP_message3(sr, packet->buf, packet->iface, 3, 1);
                packet = packet->next;
            }
            sr_arpreq_destroy(cache, req);
        }

        req = nextreq;
    }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

