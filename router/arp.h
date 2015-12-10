#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_router.h"

#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024


// define
void processARP(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface);
void arpReply(struct sr_instance *sr, uint8_t *packet, struct sr_if *sendingInterface, struct sr_if *senderInterface);
void arpRequest(struct sr_instance *sr, struct sr_if *sendingInterface, uint32_t targetIP);
