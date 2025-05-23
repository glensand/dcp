#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include "raw_socket_protocol_xor.h"

void print_usage(const char* program_name) {
    printf("Usage: %s -d <dest_ip> -m <message> -k <key_file>\n", program_name);
    printf("Options:\n");
    printf("  -d <dest_ip>    Destination IP address\n");
    printf("  -m <message>    Message to send\n");
    printf("  -k <key_file>   File containing the encryption key\n");
    printf("  -h             Show this help message\n");
}

// Get local IP address that can reach the destination
const char* get_local_ip(const char* dest_ip) {
    struct ifaddrs *ifaddr, *ifa;
    static char ip[INET_ADDRSTRLEN];
    
    // Create a UDP socket for testing connectivity
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        perror("Socket creation failed");
        return NULL;
    }

    // Set up destination address
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(dest_ip);
    dest.sin_port = htons(12345);

    // Try to connect (this will choose the appropriate local interface)
    if (connect(sock, (struct sockaddr*)&dest, sizeof(dest)) == -1) {
        perror("Connect failed");
        close(sock);
        return NULL;
    }

    // Get the local address
    struct sockaddr_in local_addr;
    socklen_t len = sizeof(local_addr);
    if (getsockname(sock, (struct sockaddr*)&local_addr, &len) == -1) {
        perror("Getsockname failed");
        close(sock);
        return NULL;
    }

    // Convert IP to string
    if (inet_ntop(AF_INET, &local_addr.sin_addr, ip, INET_ADDRSTRLEN) == NULL) {
        perror("Inet_ntop failed");
        close(sock);
        return NULL;
    }

    close(sock);
    return ip;
}

// Initialize XOR context from key file
int init_xor_context(struct xor_context *ctx, const char *key_file) {
    FILE *f = fopen(key_file, "rb");
    if (!f) {
        perror("Could not open key file");
        return -1;
    }

    // Read the key
    if (fread(ctx->key, 1, XOR_KEY_SIZE, f) != XOR_KEY_SIZE) {
        perror("Could not read key");
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

// Generate random salt
void generate_random_salt(unsigned char *salt) {
    static int initialized = 0;
    if (!initialized) {
        srand(time(NULL));
        initialized = 1;
    }
    
    for (int i = 0; i < SALT_SIZE; i++) {
        salt[i] = rand() & 0xFF;
    }
}

// XOR-based encryption/decryption with key and salt
void xor_with_key(const unsigned char *data, int data_len, 
                  const unsigned char *key, int key_len,
                  const unsigned char *salt, int salt_len,
                  unsigned char *result) {
    // First, XOR with salt
    for (int i = 0; i < data_len; i++) {
        result[i] = data[i] ^ salt[i % salt_len];
    }
    
    // Then, XOR with key
    for (int i = 0; i < data_len; i++) {
        result[i] = result[i] ^ key[i % key_len];
    }
}

// Encrypt payload using XOR
void encrypt_payload(struct xor_context *ctx, const unsigned char *plaintext, int plaintext_len,
                    unsigned char *salt, unsigned char *ciphertext) {
    // Generate random salt
    generate_random_salt(salt);
    
    // Encrypt using XOR with key and salt
    xor_with_key(plaintext, plaintext_len, ctx->key, XOR_KEY_SIZE, salt, SALT_SIZE, ciphertext);
}

// Implementation of the checksum calculation function
unsigned short calculate_checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    short answer;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;

    return answer;
}

int main(int argc, char *argv[]) {
    char *dest_ip = NULL;
    char *message = NULL;
    char *key_file = NULL;
    int opt;

    // Parse command line arguments
    while ((opt = getopt(argc, argv, "d:m:k:h")) != -1) {
        switch (opt) {
            case 'd':
                dest_ip = optarg;
                break;
            case 'm':
                message = optarg;
                break;
            case 'k':
                key_file = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
            default:
                print_usage(argv[0]);
                exit(1);
        }
    }

    // Validate arguments
    if (dest_ip == NULL || message == NULL || key_file == NULL) {
        printf("Error: Destination IP, message, and key file are required\n");
        print_usage(argv[0]);
        exit(1);
    }

    // Initialize encryption context
    struct xor_context xor_ctx;
    if (init_xor_context(&xor_ctx, key_file) < 0) {
        exit(1);
    }

    // Get local IP address
    const char* source_ip = get_local_ip(dest_ip);
    if (source_ip == NULL) {
        printf("Error: Could not determine local IP address\n");
        exit(1);
    }
    printf("Using local IP address: %s\n", source_ip);

    // Create raw socket
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("Socket creation error");
        exit(1);
    }

    // Set socket options
    int one = 1;
    const int *val = &one;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("setsockopt error");
        close(sockfd);
        exit(1);
    }

    // Prepare the packet
    struct custom_packet packet;
    static uint16_t sequence_number = 0;
    int message_len = strlen(message);

    // Clear the packet buffer
    memset(&packet, 0, sizeof(packet));

    // Encrypt the message
    encrypt_payload(&xor_ctx, (unsigned char *)message, message_len,
                   packet.msg_header.salt, (unsigned char *)packet.payload);

    // Fill in the IP header
    packet.ip.ip_hl = 5;
    packet.ip.ip_v = 4;
    packet.ip.ip_tos = 0;
    packet.ip.ip_len = sizeof(struct ipheader) + sizeof(struct message_header) + message_len;
    packet.ip.ip_id = htons(54321);
    packet.ip.ip_off = 0;
    packet.ip.ip_ttl = 255;
    packet.ip.ip_p = PROTOCOL_NUM;
    packet.ip.ip_sum = 0;
    packet.ip.ip_src.s_addr = inet_addr(source_ip);
    packet.ip.ip_dst.s_addr = inet_addr(dest_ip);

    // Fill in the message header
    packet.msg_header.magic = htonl(MAGIC_NUMBER);
    packet.msg_header.type = htons(MSG_DATA);
    packet.msg_header.sequence = htons(sequence_number++);
    packet.msg_header.payload_length = htonl(message_len);

    // Calculate the IP checksum
    packet.ip.ip_sum = calculate_checksum((unsigned short *)&packet, packet.ip.ip_len);

    // Set up destination address
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = packet.ip.ip_dst.s_addr;

    // Send the packet
    if (sendto(sockfd, &packet, packet.ip.ip_len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto error");
        close(sockfd);
        exit(1);
    }

    printf("Encrypted packet sent successfully to %s\n", dest_ip);
    printf("Original message: %s\n", message);
    printf("Message length: %d bytes\n", message_len);

    close(sockfd);
    return 0;
} 