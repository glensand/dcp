#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <netdb.h>
#include "raw_socket_protocol_xor.h"

void print_usage(const char* program_name) {
    printf("Usage: %s -k <key_file> [-i <interface>]\n", program_name);
    printf("Options:\n");
    printf("  -k <key_file>   File containing the encryption key\n");
    printf("  -i <interface>  Network interface to listen on (optional)\n");
    printf("  -h             Show this help message\n");
}

void list_interfaces() {
    struct ifaddrs *ifaddr, *ifa;
    int family;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(1);
    }

    printf("Available network interfaces:\n");
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;
        if (family == AF_INET) {
            printf("* %s\n", ifa->ifa_name);
            getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                       host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            printf("  IPv4: %s\n", host);
        }
    }

    freeifaddrs(ifaddr);
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

// Decrypt payload using XOR
void decrypt_payload(struct xor_context *ctx, const unsigned char *ciphertext, int ciphertext_len,
                    const unsigned char *salt, unsigned char *plaintext) {
    // XOR decryption is the same operation as encryption
    xor_with_key(ciphertext, ciphertext_len, ctx->key, XOR_KEY_SIZE, salt, SALT_SIZE, plaintext);
}

int main(int argc, char *argv[]) {
    char *interface = NULL;
    char *key_file = NULL;
    int opt;

    // Parse command line arguments
    while ((opt = getopt(argc, argv, "i:k:h")) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;
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
    if (key_file == NULL) {
        printf("Error: Key file is required\n");
        print_usage(argv[0]);
        exit(1);
    }

    // List available interfaces if none specified
    if (interface == NULL) {
        list_interfaces();
        printf("\nNo interface specified, listening on all interfaces.\n");
    }

    // Initialize encryption context
    struct xor_context xor_ctx;
    if (init_xor_context(&xor_ctx, key_file) < 0) {
        exit(1);
    }

    // Create raw socket
    int sockfd = socket(AF_INET, SOCK_RAW, PROTOCOL_NUM);
    if (sockfd < 0) {
        perror("Socket creation error");
        exit(1);
    }

    // Bind to specific interface if provided
    if (interface != NULL) {
        // Get the interface index using if_nametoindex
        unsigned int if_index = if_nametoindex(interface);
        if (if_index == 0) {
            perror("Failed to get interface index");
            close(sockfd);
            exit(1);
        }
        
        // On macOS, use IP_BOUND_IF to bind to a specific interface
        if (setsockopt(sockfd, IPPROTO_IP, IP_BOUND_IF, &if_index, sizeof(if_index)) < 0) {
            perror("Failed to bind to interface");
            close(sockfd);
            exit(1);
        }
        printf("Listening on interface: %s\n", interface);
    }

    printf("Waiting for encrypted messages...\n");

    while (1) {
        struct custom_packet packet;
        struct sockaddr_in source_addr;
        socklen_t addr_len = sizeof(source_addr);
        unsigned char decrypted_payload[PACKET_SIZE];

        // Receive packet
        ssize_t packet_len = recvfrom(sockfd, &packet, sizeof(packet), 0,
                                    (struct sockaddr*)&source_addr, &addr_len);
        if (packet_len < 0) {
            perror("Packet receive error");
            continue;
        }

        // Validate magic number
        if (ntohl(packet.msg_header.magic) != MAGIC_NUMBER) {
            continue;  // Not our protocol
        }

        // Get message details
        uint16_t msg_type = ntohs(packet.msg_header.type);
        uint16_t sequence = ntohs(packet.msg_header.sequence);
        uint32_t payload_length = ntohl(packet.msg_header.payload_length);

        // Decrypt the payload
        decrypt_payload(&xor_ctx, (unsigned char *)packet.payload, payload_length,
                       packet.msg_header.salt, decrypted_payload);

        // Null terminate the decrypted payload
        decrypted_payload[payload_length] = '\0';

        // Print message details
        printf("\nReceived encrypted message from %s\n", inet_ntoa(source_addr.sin_addr));
        printf("Message type: %d\n", msg_type);
        printf("Sequence: %d\n", sequence);
        printf("Message length: %d bytes\n", payload_length);
        printf("Decrypted message: %s\n", decrypted_payload);
    }

    close(sockfd);
    return 0;
} 