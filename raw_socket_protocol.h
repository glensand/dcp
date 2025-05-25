#pragma once

#include <netinet/in.h>
#include <stdint.h>

#define PACKET_SIZE 4096
#define PROTOCOL_NUM 200
#define MAGIC_NUMBER 0x1234ABCD

// Message header
struct message_header {
    uint32_t magic;          // Magic number to identify our protocol
    uint16_t sequence;       // Sequence number
    uint32_t payload_length; // Length of the payload
};

// Our custom packet structure
struct custom_packet {
    struct message_header msg_header;
    char payload[PACKET_SIZE - sizeof(struct message_header)];
};

// Function declarations
unsigned short calculate_checksum(unsigned short *ptr, int nbytes);
