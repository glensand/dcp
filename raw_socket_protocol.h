#pragma once

#include <netinet/ip.h>
#include <netinet/in.h>
#include <stdint.h>

#define PACKET_SIZE 4096
#define PROTOCOL_NUM 200
#define MAGIC_NUMBER 0x1234ABCD

// Message types
enum MessageType {
    MSG_HELLO = 1,
    MSG_DATA = 2,
    MSG_ACK = 3,
    MSG_GOODBYE = 4
};

// IP header structure
struct ipheader {
    unsigned char ip_hl:4, ip_v:4;
    unsigned char ip_tos;
    unsigned short int ip_len;
    unsigned short int ip_id;
    unsigned short int ip_off;
    unsigned char ip_ttl;
    unsigned char ip_p;
    unsigned short int ip_sum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
};

// Custom message header
struct message_header {
    uint32_t magic;          // Magic number to identify our protocol
    uint16_t type;           // Message type
    uint16_t sequence;       // Sequence number
    uint32_t payload_length; // Length of the payload
};

// Our custom packet structure
struct custom_packet {
    struct ipheader ip;
    struct message_header msg_header;
    char payload[PACKET_SIZE - sizeof(struct ipheader) - sizeof(struct message_header)];
};

// Utility function declaration
unsigned short calculate_checksum(unsigned short *ptr, int nbytes);
