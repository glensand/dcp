#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netdb.h>
#include "raw_socket_protocol.h"

void print_usage(const char* program_name) {
    printf("Usage: %s [-i <interface>]\n", program_name);
    printf("Options:\n");
    printf("  -i <interface>   Network interface to listen on (optional, listens on all interfaces if not specified)\n");
    printf("  -h              Show this help message\n");
}

// Print all available network interfaces and their IP addresses
void print_interfaces() {
    struct ifaddrs *ifaddr, *ifa;
    int family;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(1);
    }

    printf("\nAvailable network interfaces:\n");
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        // We're only interested in IPv4 interfaces
        if (family == AF_INET) {
            printf("%-8s ", ifa->ifa_name);
            
            // Get IP address
            if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                           host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) == 0) {
                printf("IPv4: %s\n", host);
            }
        }
    }
    printf("\n");

    freeifaddrs(ifaddr);
}

// Get IP address for a specific interface
const char* get_interface_ip(const char* interface_name) {
    struct ifaddrs *ifaddr, *ifa;
    static char host[NI_MAXHOST];
    int found = 0;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return NULL;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET && 
            strcmp(ifa->ifa_name, interface_name) == 0) {
            if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                           host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) == 0) {
                found = 1;
                break;
            }
        }
    }

    freeifaddrs(ifaddr);
    return found ? host : NULL;
}

// Handle received message based on type
void handle_message(const struct custom_packet *packet, const struct sockaddr_in *source) {
    // First verify magic number
    if (ntohl(packet->msg_header.magic) != MAGIC_NUMBER) {
        printf("Invalid magic number received, ignoring packet\n");
        return;
    }

    // Handle message based on type
    switch(ntohs(packet->msg_header.type)) {
        case MSG_HELLO:
            printf("Received HELLO message from %s\n", inet_ntoa(source->sin_addr));
            printf("Sequence: %d\n", ntohs(packet->msg_header.sequence));
            break;

        case MSG_DATA:
            printf("Received DATA message from %s\n", inet_ntoa(source->sin_addr));
            printf("Sequence: %d\n", ntohs(packet->msg_header.sequence));
            printf("Payload length: %d\n", ntohl(packet->msg_header.payload_length));
            printf("Payload: %.*s\n", ntohl(packet->msg_header.payload_length), packet->payload);
            break;

        case MSG_ACK:
            printf("Received ACK message from %s\n", inet_ntoa(source->sin_addr));
            printf("Sequence: %d\n", ntohs(packet->msg_header.sequence));
            break;

        case MSG_GOODBYE:
            printf("Received GOODBYE message from %s\n", inet_ntoa(source->sin_addr));
            printf("Sequence: %d\n", ntohs(packet->msg_header.sequence));
            break;

        default:
            printf("Unknown message type received: %d\n", ntohs(packet->msg_header.type));
    }
}

int main(int argc, char *argv[]) {
    char *interface_name = NULL;
    int opt;

    // Parse command line arguments
    while ((opt = getopt(argc, argv, "i:h")) != -1) {
        switch (opt) {
            case 'i':
                interface_name = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
            default:
                print_usage(argv[0]);
                exit(1);
        }
    }

    // Print available interfaces
    print_interfaces();

    // Create receiving socket for our custom protocol
    int recv_sock = socket(AF_INET, SOCK_RAW, PROTOCOL_NUM);
    if (recv_sock < 0) {
        perror("Receive socket creation error");
        exit(1);
    }

    // Setup for receiving packets
    struct custom_packet recv_packet;
    struct sockaddr_in source;
    socklen_t source_len = sizeof(source);

    // Bind to specific interface if provided
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;

    if (interface_name != NULL) {
        const char* ip = get_interface_ip(interface_name);
        if (ip == NULL) {
            printf("Error: Could not find IP address for interface %s\n", interface_name);
            close(recv_sock);
            exit(1);
        }
        server_addr.sin_addr.s_addr = inet_addr(ip);
        printf("Listening on interface %s (IP: %s)\n", interface_name, ip);
    } else {
        server_addr.sin_addr.s_addr = INADDR_ANY;
        printf("Listening on all interfaces\n");
    }

    if (bind(recv_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(recv_sock);
        exit(1);
    }

    printf("Server started with protocol number %d\n", PROTOCOL_NUM);

    // Receive packets
    while (1) {
        ssize_t packet_len = recvfrom(recv_sock, &recv_packet, sizeof(recv_packet), 0,
                                    (struct sockaddr *)&source, &source_len);
        
        if (packet_len < 0) {
            perror("Packet receive error");
            continue;
        }

        // Handle the received message
        handle_message(&recv_packet, &source);
    }

    close(recv_sock);
    return 0;
} 