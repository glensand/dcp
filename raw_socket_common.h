#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netdb.h>
#include "raw_socket_protocol.h"

#define MAX_PAYLOAD_SIZE 1024  // Maximum size for packet payload

// Sequence number masks
#define SERVER_SEQUENCE_MASK 0x8000   // High bit set for server messages
#define CLIENT_SEQUENCE_MASK 0x7FFF   // High bit clear for client messages
#define SEQUENCE_NUMBER_MASK 0x7FFF   // Mask to get the actual sequence number

// Helper functions for sequence numbers
inline uint16_t make_server_sequence(uint16_t seq) {
    return (seq & CLIENT_SEQUENCE_MASK) | SERVER_SEQUENCE_MASK;
}

inline uint16_t make_client_sequence(uint16_t seq) {
    return seq & CLIENT_SEQUENCE_MASK;
}

inline bool is_server_sequence(uint16_t seq) {
    return (seq & SERVER_SEQUENCE_MASK) != 0;
}

inline bool is_client_sequence(uint16_t seq) {
    return (seq & SERVER_SEQUENCE_MASK) == 0;
}

inline uint16_t get_base_sequence(uint16_t seq) {
    return seq & SEQUENCE_NUMBER_MASK;
}

// Debug function to print packet details
inline void debug_print_packet(const struct custom_packet *packet, const struct sockaddr_in *peer, const char *prefix) {
    printf("\n%s Packet Debug Info:\n", prefix);
    if (peer) {
        printf("Peer IP: %s\n", inet_ntoa(peer->sin_addr));
    }
    printf("Message Header:\n");
    printf("  Magic Number (raw): 0x%08X\n", packet->msg_header.magic);
    printf("  Magic Number (converted): 0x%08X (expected: 0x%08X)\n", 
           ntohl(packet->msg_header.magic), MAGIC_NUMBER);
    printf("  Sequence: %d\n", ntohs(packet->msg_header.sequence));
    printf("  Payload Length: %d\n", ntohl(packet->msg_header.payload_length));
}

// Calculate IP header checksum
inline unsigned short calculate_checksum(unsigned short *ptr, int nbytes) {
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

// Print all available network interfaces and their IP addresses
inline void print_interfaces() {
    struct ifaddrs *ifaddr, *ifa;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(1);
    }

    printf("\nAvailable network interfaces:\n");
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        int family = ifa->ifa_addr->sa_family;

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
inline const char* get_interface_ip(const char* interface_name) {
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

// Get local IP address that can reach the destination
inline const char* get_local_ip(const char* dest_ip) {
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

// Print socket settings and buffer sizes
inline void print_socket_settings(int sockfd) {
    int value;
    socklen_t value_len = sizeof(value);

    printf("\nSocket Settings:\n");
    printf("---------------\n");

    // Get send buffer size
    if (getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &value, &value_len) == 0) {
        printf("Send buffer size: %d bytes\n", value);
    } else {
        printf("Failed to get send buffer size: %s\n", strerror(errno));
    }

    // Get receive buffer size
    if (getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &value, &value_len) == 0) {
        printf("Receive buffer size: %d bytes\n", value);
    } else {
        printf("Failed to get receive buffer size: %s\n", strerror(errno));
    }

    // Get socket type
    if (getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &value, &value_len) == 0) {
        printf("Socket type: %d (SOCK_RAW)\n", value);
    } else {
        printf("Failed to get socket type: %s\n", strerror(errno));
    }

    // Get socket error flag
    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &value, &value_len) == 0) {
        printf("Socket error state: %d (%s)\n", value, value == 0 ? "No error" : strerror(value));
    } else {
        printf("Failed to get socket error state: %s\n", strerror(errno));
    }

    // Get socket flags
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags != -1) {
        printf("Socket flags: 0x%x\n", flags);
        printf("  O_NONBLOCK: %s\n", (flags & O_NONBLOCK) ? "Yes" : "No");
        printf("  O_ASYNC: %s\n", (flags & O_ASYNC) ? "Yes" : "No");
    } else {
        printf("Failed to get socket flags: %s\n", strerror(errno));
    }

    // Get interface list and their MTUs
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == 0) {
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
                struct ifreq ifr;
                memset(&ifr, 0, sizeof(ifr));
                strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ-1);
                if (ioctl(sockfd, SIOCGIFMTU, &ifr) == 0) {
                    printf("Interface %s MTU: %d bytes\n", ifa->ifa_name, ifr.ifr_mtu);
                }
            }
        }
        freeifaddrs(ifaddr);
    }

    printf("\n");
} 