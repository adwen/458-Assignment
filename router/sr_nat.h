
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>

// Added
#define internalNat "eth1"
#define externalNat "eth2"
#define MINIMUM_PORT_NUMBER 1024        // Don't use 0-1023
#define MAXIMUM_PORT_NUMBER 65535

// Given
typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

// Connection States
typedef enum {
    SENT_SYN,
    SYN_RCVD,
    ESTAB,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    CLOSING,
    LAST_ACK
} connectionStates;

// Added stuff to this
struct sr_nat_connection {
    /* add TCP connection state data embers here */
    connectionStates state;
    uint32_t ip_ext;
    uint16_t externalPort;
    time_t last_updated;

    struct sr_nat_connection *next;
};

// Given, probably shouldnt change
struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

// I think this is wrong
struct synMap {
    uint8_t *payload;
    unsigned int mappingLength;
    uint32_t sourceIP;
    uint32_t destinationIP;
    uint16_t sourcePort;
    uint16_t sourceDestination;
    time_t receivedTime;
    int drop;
    struct synMap *next;
};


// Nat Structure
struct sr_nat {
    struct sr_nat_mapping *nat_mappings;
    /* add any fields here */
    int IQT;    // ICMP QUERY TIMEOUT
    int TET;    // TCP ESTABLISHED TIMEOUT
    int TTT;    // TCP TRANSITORY TIMEOUT
    uint16_t icmpID;
    uint16_t tcpPort;
    struct synMap *syn_mappings;

    /* threading */
    pthread_mutex_t lock;
    pthread_mutexattr_t attr;
    pthread_attr_t thread_attr;
    pthread_t thread;
};


// Everything below is given
int   sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );


#endif


// Function declerations
void connectionCleanUp(struct sr_nat *nat, struct sr_nat_mapping *mapping);
void killConnection(struct sr_nat *nat, struct sr_nat_mapping *mapping, struct sr_nat_connection *connection);
void killMapping(struct sr_nat *nat, struct sr_nat_mapping *mapEntry);
uint16_t assignNewExternalPortNumber(struct sr_nat *nat, sr_nat_mapping_type type);
