#indef HEADERS_H
#define HEADERS_H
#include <stdint.h>

struct enet_header {
	uint8_t dest_addr[6];
	uint8_t src_addr[6];
	uint16_t enet_type;
}__attributes__((packed));
