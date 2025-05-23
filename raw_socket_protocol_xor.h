#ifndef RAW_SOCKET_PROTOCOL_XOR_H
#define RAW_SOCKET_PROTOCOL_XOR_H

#include <netinet/ip.h>
#include <netinet/in.h>
#include <stdint.h>

#define PACKET_SIZE 4096
#define PROTOCOL_NUM 200
#define MAGIC_NUMBER 0x1234ABCD
#define XOR_KEY_SIZE 32  // Using 32 bytes for the key
#define SALT_SIZE 8     // Random salt for each message

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

// Custom message header with encryption info
struct message_header {
    uint32_t magic;          // Magic number to identify our protocol
    uint16_t type;           // Message type
    uint16_t sequence;       // Sequence number
    uint32_t payload_length; // Length of the encrypted payload
    unsigned char salt[SALT_SIZE];  // Random salt for encryption
};

// Our custom packet structure
struct custom_packet {
    struct ipheader ip;
    struct message_header msg_header;
    char payload[PACKET_SIZE - sizeof(struct ipheader) - sizeof(struct message_header)];
};

// Simple encryption context
struct xor_context {
    unsigned char key[XOR_KEY_SIZE];
};

// Function declarations
unsigned short calculate_checksum(unsigned short *ptr, int nbytes);

// Encryption/Decryption functions
int init_xor_context(struct xor_context *ctx, const char *key_file);
void encrypt_payload(struct xor_context *ctx, const unsigned char *plaintext, int plaintext_len,
                    unsigned char *salt, unsigned char *ciphertext);
void decrypt_payload(struct xor_context *ctx, const unsigned char *ciphertext, int ciphertext_len,
                    const unsigned char *salt, unsigned char *plaintext);

// Helper functions
void generate_random_salt(unsigned char *salt);
void xor_with_key(const unsigned char *data, int data_len, 
                  const unsigned char *key, int key_len,
                  const unsigned char *salt, int salt_len,
                  unsigned char *result);

#endif // RAW_SOCKET_PROTOCOL_XOR_H 