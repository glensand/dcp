#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <errno.h>
#include "raw_socket_protocol.h"

void print_usage(const char* program_name) {
    printf("Usage: %s -d <dest_ip> -m <message>\n", program_name);
    printf("Options:\n");
    printf("  -d <dest_ip>    Destination IP address\n");
    printf("  -m <message>    Message to send\n");
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
    dest.sin_port = htons(12345); // Any port will do as we won't actually connect

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

// Implementation of the checksum calculation function declared in the header
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
    int opt;

    // Parse command line arguments
    while ((opt = getopt(argc, argv, "d:m:h")) != -1) {
        switch (opt) {
            case 'd':
                dest_ip = optarg;
                break;
            case 'm':
                message = optarg;
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
    if (dest_ip == NULL || message == NULL) {
        printf("Error: Both destination IP and message are required\n");
        print_usage(argv[0]);
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

    // Clear the packet buffer
    memset(&packet, 0, sizeof(packet));

    // Fill in the IP header
    packet.ip.ip_hl = 5;
    packet.ip.ip_v = 4;
    packet.ip.ip_tos = 0;
    packet.ip.ip_len = sizeof(struct ipheader) + sizeof(struct message_header) + strlen(message);
    packet.ip.ip_id = htons(54321);
    packet.ip.ip_off = 0;
    packet.ip.ip_ttl = 255;
    packet.ip.ip_p = PROTOCOL_NUM;
    packet.ip.ip_sum = 0;
    packet.ip.ip_src.s_addr = inet_addr(source_ip);
    packet.ip.ip_dst.s_addr = inet_addr(dest_ip);

    // Fill in the message header
    packet.msg_header.magic = htonl(MAGIC_NUMBER);
    packet.msg_header.type = htons(MSG_DATA);  // Always send DATA messages
    packet.msg_header.sequence = htons(sequence_number++);
    packet.msg_header.payload_length = htonl(strlen(message));
    
    // Add payload
    strncpy(packet.payload, message, sizeof(packet.payload) - 1);

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

    printf("Packet sent successfully to %s\n", dest_ip);
    printf("Payload: %s\n", message);

    close(sockfd);
    return 0;
} 