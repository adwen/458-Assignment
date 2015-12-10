#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>

#include "sr_protocol.h"
#include "sr_nat.h"

int sr_nat_init(struct sr_nat *nat) {  /* Initializes the nat */

    assert(nat);

    /* Acquire mutex lock */
    pthread_mutexattr_init(&(nat->attr));
    pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

    /* Initialize timeout thread */

    pthread_attr_init(&(nat->thread_attr));
    pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

    /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

    nat->nat_mappings = NULL;
    /* Initialize any variables here */
    nat->icmpID = MINIMUM_PORT_NUMBER;
    nat->tcpPort = MINIMUM_PORT_NUMBER;

    return success;
}

int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

    pthread_mutex_lock(&(nat->lock));

    /* free nat memory here */

    pthread_kill(nat->thread, SIGKILL);
    return pthread_mutex_destroy(&(nat->lock)) && pthread_mutexattr_destroy(&(nat->attr));
}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */

    struct sr_nat *nat = (struct sr_nat *)nat_ptr;

    while (1) {
        sleep(1.0);

        pthread_mutex_lock(&(nat->lock));

        time_t curtime = time(NULL);

        /* handle periodic tasks here */

        // Initialize the mapEntryPointer pointers
        struct sr_nat_mapping *mapEntryPointer = NULL;
        struct sr_nat_mapping *next = NULL;         //TODO: Check if this is efficient

        mapEntryPointer = nat->nat_mappings;

        // Go through each mapping
        while (mapEntryPointer) {

            // Hold a pointer to the next mapping pointer
            next = mapEntryPointer->next;

            // Case where mapping type is TCP
            if (mapEntryPointer->type == nat_mapping_tcp) {

                connectionCleanUp(nat, mapEntryPointer);

                if (!mapEntryPointer->conns) {
                    killMapping(nat, mapEntryPointer);
                }

            }

            // Case where the mapping type is ICMP
            if (mapEntryPointer->type == nat_mapping_icmp) {
                if (difftime(curtime, mapEntryPointer->last_updated) > nat->IQT) {
                    killMapping(nat, mapEntryPointer);
                }

            }
            mapEntryPointer = next;
        }

        pthread_mutex_unlock(&(nat->lock));
    }

    return NULL;
}

/* Get the mapEntryPointer associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat, uint16_t aux_ext, sr_nat_mapping_type type)
{
    pthread_mutex_lock(&(nat->lock));

    /* handle lookup here, malloc and assign to copy */
    struct sr_nat_mapping *copy = NULL;     // Used to hold mapping
    struct sr_nat_mapping *mapEntryPointer = NULL;
    struct sr_nat_mapping *mappingIterator = NULL;

    // For every mapping that is a non null entity
    for (mappingIterator = nat->nat_mappings; mappingIterator != NULL; mappingIterator = mappingIterator->next) {

        // Check if the external port is the same as the given port and the given type matches
        // If so: add make the pointer to point to the current mapping
        if (mappingIterator->aux_ext == aux_ext) {
            if(mappingIterator->type == type){
                mapEntryPointer = mappingIterator;
                break;
            }
        }
    }

    // if a mapping for external port is found
    if (mapEntryPointer != NULL) {

        // Set the last updated time to now (time(NULL))
        mapEntryPointer->last_updated = time(NULL);

        // Set the copy to the mapping we found
        copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
        memcpy(copy, mapEntryPointer, sizeof(struct sr_nat_mapping));
    }

    pthread_mutex_unlock(&(nat->lock));

    return copy;
}

/* Get the mapEntryPointer associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat, uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type )
{
    pthread_mutex_lock(&(nat->lock));

    /* handle lookup here, malloc and assign to copy. */
    struct sr_nat_mapping *copy = NULL;
    struct sr_nat_mapping *mapEntryPointer = NULL;
    struct sr_nat_mapping *mappingIterator = NULL;

    // For every mapping entry that is non null
    for (mappingIterator = nat->nat_mappings; mappingIterator != NULL; mappingIterator = mappingIterator->next) {

        // Check if the internal IP address is the same as given address AND the internal port matches AND the type matches
        if (mappingIterator->ip_int == ip_int) {
            if (mappingIterator->aux_int == aux_int){
                if (mappingIterator->type == type){
                    mapEntryPointer = mappingIterator;
                    break;
                }
            }
        }
    }

    // If we found a map entry
    if (mapEntryPointer) {

        // Update to NOW
        mapEntryPointer->last_updated = time(NULL);

        // Set copy to the mapping we found
        copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
        memcpy(copy, mapEntryPointer, sizeof(struct sr_nat_mapping));
    }

    pthread_mutex_unlock(&(nat->lock));

    return copy;
}


/* Insert a new newMapEntry into the nat's newMapEntry table.
   Actually returns a copy to the new newMapEntry, for thread safety. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat, uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type)
{
    pthread_mutex_lock(&(nat->lock));

    /* handle insert here, create a newMapEntry, and then return a copy of it */
    struct sr_nat_mapping *copy = NULL;
    struct sr_nat_mapping *newMapEntry = NULL;
    size_t natMapSize = sizeof(struct sr_nat_mapping);

    newMapEntry = (struct sr_nat_mapping *) calloc(1, natMapSize);

    // Fill out the map fields and add it to the existing map entries
    newMapEntry->type = type;
    newMapEntry->ip_int = ip_int;
    newMapEntry->aux_int = aux_int;
    newMapEntry->aux_ext = assignNewExternalPortNumber(nat, type);
    newMapEntry->last_updated = time(NULL);
    newMapEntry->next = nat->nat_mappings;  // Link it
    nat->nat_mappings = newMapEntry;

    // Return a copy of it
    copy = (struct sr_nat_mapping *) malloc(natMapSize);
    memcpy(copy, newMapEntry, sizeof(struct sr_nat_mapping));
    pthread_mutex_unlock(&(nat->lock));

    return copy;
}

void connectionCleanUp(struct sr_nat *nat, struct sr_nat_mapping *mapping)
{

    // Variables
    int tcpEstablishedIdleTimeout = nat->TET;
    int tcpTransitoryIdleTimeout = nat->TTT;
    struct sr_nat_connection *connectionPointer = NULL;
    struct sr_nat_connection *nextConnection = NULL;

    // Pointer to list of connections
    connectionPointer = mapping->conns;

    // While there is still a connectionPointer inhte list, see if they need to be removed
    while (connectionPointer != NULL) {

        // Store pointer to next connection
        nextConnection = connectionPointer->next;

        switch (connectionPointer->state) {
            case ESTAB:
            case FIN_WAIT_1:
            case FIN_WAIT_2:
            case CLOSE_WAIT: {
                if (connectionPointer->last_updated > tcpEstablishedIdleTimeout) {
                    killConnection(nat, mapping, connectionPointer);
                }

                break;
            }
            case SENT_SYN:
            case SYN_RCVD:
            case CLOSING:
            case LAST_ACK: {
                if (connectionPointer->last_updated > tcpTransitoryIdleTimeout) {
                    killConnection(nat, mapping, connectionPointer);
                }
                break;
            }
        }

        // Go to next connection
        connectionPointer = nextConnection;
    }
}

void killConnection(struct sr_nat *nat, struct sr_nat_mapping *mapping, struct sr_nat_connection *connection)
{
    // Critical area operation: Rofl CSC369
    pthread_mutex_lock(&(nat->lock));

    // If the given connection is not null
    if (connection != NULL) {

        struct sr_nat_connection *connectionPointer, *previousConnection = NULL, *next = NULL;

        // For each connection in the list of connections,
        // check if it matches the given connection and rebuild the LL
        for (connectionPointer = mapping->conns; connectionPointer != NULL; connectionPointer = connectionPointer->next) {

            // Found match
            if (connection == connectionPointer) {

                // If the connection has a previous link, need to restructure
                if (previousConnection != NULL) {
                    next = connectionPointer->next;
                    previousConnection->next = next;
                }

                // If connection is the head, can simply append
                if (previousConnection == NULL) {
                    next = connectionPointer->next;
                    mapping->conns = next;
                }

                break;
            }

            // Check next connection in the list if not found
            previousConnection = connectionPointer;
        }

        free(connection);
    }

    pthread_mutex_unlock(&(nat->lock));
}

void killMapping(struct sr_nat *nat, struct sr_nat_mapping *mapEntry)
{

    // Critical Operation Start
    pthread_mutex_lock(&(nat->lock));

    // If the map entry is not null:
    if (mapEntry != NULL) {

        struct sr_nat_mapping *mapListPointer, *prev = NULL, *next = NULL;

        // for each valid mapListPointer entry in hte list, check if we have a match
        for (mapListPointer = nat->nat_mappings; mapListPointer != NULL; mapListPointer = mapListPointer->next) {

            // Match found
            if (mapListPointer == mapEntry) {

                // Head of LL
                if (prev == NULL){
                    next = mapListPointer->next;
                    nat->nat_mappings = next;
                }

                // Not the head of LL
                if (prev != NULL) {
                    next = mapListPointer->next;
                    prev->next = next;
                }
                break;
            }

            // Go next
            prev = mapListPointer;
        }

        // Free all connections associated with the map entry we are going to kill
        struct sr_nat_connection *connection, *nextConnection;
        for (connection = mapEntry->conns; connection; connection = nextConnection) {
            nextConnection = connection->next;
            free(connection);
        }

        // Free the map entry
        free(mapEntry);
    }

    pthread_mutex_unlock(&(nat->lock));
}



uint16_t assignNewExternalPortNumber(struct sr_nat *nat, sr_nat_mapping_type type)
{

    // Initialize next external port #
    uint16_t newPortNumber = 0;

    // If the type specified is TCP, aux_ent should be the tcp port
    if (type == nat_mapping_tcp) {
        newPortNumber = nat->tcpPort;
    }

    // If the type specified is ICMP, aux_ent should refer to icmp id
    if (type == nat_mapping_icmp) {
        newPortNumber = nat->icmpID;
    }

    // Get pointer to the nat mapping list
    struct sr_nat_mapping *mappingEntryPointer = nat->nat_mappings;

    // Go through the mapping list, looking for matching types and matching external ip addresses
    while (mappingEntryPointer) {

        if (mappingEntryPointer->aux_ext == htons(newPortNumber) && mappingEntryPointer->type == type) {

            // Wrap port numbers around, just make sure we dont use 0-1023
            if (newPortNumber == MAXIMUM_PORT_NUMBER) {
                newPortNumber = MINIMUM_PORT_NUMBER;
            }

            else {
                newPortNumber = newPortNumber + 1;
            }

            // Reset if found
            mappingEntryPointer = nat->nat_mappings;
        }

        // Traverse to the next entry if no match
        else {
            mappingEntryPointer = mappingEntryPointer->next;
        }
    }

    switch (type){

        case nat_mapping_tcp:
            // If the external port # hits the limit, wrap around
            if (newPortNumber == MAXIMUM_PORT_NUMBER) {
                nat->tcpPort = MINIMUM_PORT_NUMBER;
            }

            // Otherwise can increment normally
            else {
                nat->tcpPort = newPortNumber + 1;
            }
            break;

        case nat_mapping_icmp:
            // If the external port # hits the limit, wrap around
            if (newPortNumber == MAXIMUM_PORT_NUMBER) {
                nat->icmpID = MINIMUM_PORT_NUMBER;
            }

            // Otherwise can increment normally
            else {
                nat->icmpID = newPortNumber + 1;
            }
            break;
    }

    return htons(newPortNumber);
}
