#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>
#include "raw_socket_common.h"

// Global flag for timeout
volatile sig_atomic_t timeout_occurred = 0;

// Track our sent sequence number to identify our own packets
uint16_t sent_sequence = 0;

void alarm_handler(int signum) {
    if (signum == SIGALRM) {
        timeout_occurred = 1;
    }
}

void print_usage(const char* program_name) {
    printf("Usage: %s -d <dest_ip> -m <message>\n", program_name);
    printf("Options:\n");
    printf("  -d <dest_ip>    Destination IP address\n");
    printf("  -m <message>    Message to send\n");
    printf("  -h             Show this help message\n");
}

// Handle received message
void handle_response(const struct custom_packet *packet, const struct sockaddr_in *source) {
    // Print debug info
    debug_print_packet(packet, source, "Received");

    // First verify magic number
    uint32_t received_magic = ntohl(packet->msg_header.magic);
    if (received_magic != MAGIC_NUMBER) {
        printf("Invalid magic number received: 0x%08X, expected: 0x%08X\n", 
               received_magic, MAGIC_NUMBER);
        return;
    }

    uint16_t sequence = ntohs(packet->msg_header.sequence);
    uint32_t payload_length = ntohl(packet->msg_header.payload_length);

    // Validate payload length
    if (payload_length > sizeof(packet->payload)) {
        printf("Invalid payload length: %u, max allowed: %lu\n", 
               payload_length, sizeof(packet->payload));
        return;
    }

    printf("Received echo from server %s\n", inet_ntoa(source->sin_addr));
    printf("Sequence: %d\n", sequence);
    if (payload_length > 0) {
        printf("Echo payload: %.*s\n", payload_length, packet->payload);
    }
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

    // Set up signal handling for timeout
    struct sigaction sa;
    sa.sa_handler = alarm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGALRM, &sa, NULL);

    // Get local IP address
    const char* source_ip = get_local_ip(dest_ip);
    if (source_ip == NULL) {
        printf("Error: Could not determine local IP address\n");
        exit(1);
    }
    printf("Using local IP address: %s\n", source_ip);

    // Create sending socket
    int send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (send_sock < 0) {
        perror("Send socket creation error");
        exit(1);
    }

    // Create receiving socket for our custom protocol
    int recv_sock = socket(AF_INET, SOCK_RAW, PROTOCOL_NUM);
    if (recv_sock < 0) {
        perror("Receive socket creation error");
        close(send_sock);
        exit(1);
    }

    // Set socket options
    int one = 1;
    const int *val = &one;
    if (setsockopt(send_sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("setsockopt error");
        close(send_sock);
        close(recv_sock);
        exit(1);
    }

    // Set receive socket to non-blocking mode
    int flags = fcntl(recv_sock, F_GETFL, 0);
    fcntl(recv_sock, F_SETFL, flags | O_NONBLOCK);

    // Prepare the packet - now only message header and payload
    struct {
        struct message_header header;
        char payload[MAX_PAYLOAD_SIZE];
    } packet;
    static uint16_t sequence_number = 0;
    int message_len = strlen(message);

    // Clear the packet buffer
    memset(&packet, 0, sizeof(packet));

    // Fill in the message header
    sent_sequence = sequence_number++;  // Store the sequence number we're sending
    packet.header.magic = htonl(MAGIC_NUMBER);
    packet.header.sequence = htons(make_client_sequence(sent_sequence));  // Ensure client sequence
    packet.header.payload_length = htonl(message_len);

    // Add payload
    strncpy(packet.payload, message, sizeof(packet.payload) - 1);

    // Print debug info for the packet we're about to send
    printf("\n========== SENDING PACKET ==========\n");
    printf("Destination: %s\n", dest_ip);
    printf("Total packet length: %zu bytes\n", sizeof(struct message_header) + message_len);
    printf("Sequence number: %d\n", sent_sequence);
    printf("Payload length: %d\n", message_len);
    
    printf("Packet content being sent:\n");
    printf("Message Header:\n");
    printf("  Magic Number: 0x%08X\n", ntohl(packet.header.magic));
    printf("  Sequence: %d\n", ntohs(packet.header.sequence));
    printf("  Payload Length: %d\n", ntohl(packet.header.payload_length));
    
    printf("Raw bytes being sent:\n");
    unsigned char* send_data = (unsigned char*)&packet;
    size_t total_len = sizeof(struct message_header) + message_len;
    for (size_t i = 0; i < total_len; i++) {
        printf("%02X ", send_data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
    printf("Payload as text: %s\n", message);
    printf("==================================\n\n");

    // Set up destination address
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(dest_ip);

    // Send the packet - only message header and payload
    if (sendto(send_sock, &packet, sizeof(struct message_header) + message_len, 0, 
               (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        printf("Send failed: %s (errno: %d)\n", strerror(errno), errno);
        close(send_sock);
        close(recv_sock);
        exit(1);
    }

    printf("Packet sent successfully to %s\n", dest_ip);
    printf("Payload: %s\n", message);
    printf("Waiting for server echo...\n");

    // Set up poll for receiving response
    struct pollfd pfd;
    pfd.fd = recv_sock;
    pfd.events = POLLIN;

    // Set 5-second timeout
    alarm(5);
    timeout_occurred = 0;

    // Wait for response
    while (!timeout_occurred) {
        int ready = poll(&pfd, 1, 100); // Poll every 100ms
        
        if (ready < 0) {
            if (errno == EINTR) {
                // Interrupted by signal, check timeout
                continue;
            }
            perror("poll error");
            break;
        }
        
        if (ready == 0) {
            // No data yet, continue waiting
            continue;
        }

        if (pfd.revents & POLLIN) {
            struct custom_packet recv_packet;
            struct sockaddr_in source;
            socklen_t source_len = sizeof(source);

            ssize_t packet_len = recvfrom(recv_sock, &recv_packet, sizeof(recv_packet), 0,
                                        (struct sockaddr *)&source, &source_len);
            
            if (packet_len < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;
                }
                perror("Packet receive error");
                continue;
            }

            printf("\n========== RECEIVED PACKET ==========\n");
            printf("Total packet length: %zd bytes from %s\n", 
                   packet_len, inet_ntoa(source.sin_addr));
            
            // Print entire payload area regardless of validity
            printf("Raw payload area (all bytes after IP header):\n");
            if (packet_len > sizeof(struct ipheader)) {
                size_t payload_start = sizeof(struct ipheader);
                size_t payload_len = packet_len - payload_start;
                printf("Payload length: %zu bytes\n", payload_len);
                printf("As hex: ");
                unsigned char* payload_data = (unsigned char*)&recv_packet + payload_start;
                for (size_t i = 0; i < payload_len; i++) {
                    printf("%02X ", payload_data[i]);
                    if ((i + 1) % 16 == 0) printf("\n        ");
                }
                printf("\nAs text: ");
                for (size_t i = 0; i < payload_len; i++) {
                    char c = payload_data[i];
                    printf("%c", (c >= 32 && c <= 126) ? c : '.');
                }
                printf("\n");
            } else {
                printf("No payload (packet too short)\n");
            }

            // Check if this packet is from our server
            if (source.sin_addr.s_addr == inet_addr(dest_ip)) {
                printf("\n========== RECEIVED RESPONSE ==========\n");
                printf("Source: %s\n", inet_ntoa(source.sin_addr));
                printf("Total packet length: %zd bytes\n", packet_len);
                printf("Raw packet dump (first 32 bytes):\n");
                unsigned char* raw_resp = (unsigned char*)&recv_packet;
                for (size_t i = 0; i < (packet_len < 32 ? packet_len : 32); i++) {
                    printf("%02X ", raw_resp[i]);
                    if ((i + 1) % 16 == 0) printf("\n");
                }
                printf("\n====================================\n");

                // Ensure we have enough data for IP header
                if (packet_len < sizeof(struct ipheader)) {
                    printf("Packet too small for IP header\n");
                    continue;
                }

                // First verify this is our protocol
                struct ipheader* ip = (struct ipheader*)&recv_packet;
                if (ip->ip_p != PROTOCOL_NUM) {
                    printf("Ignoring packet with wrong protocol: %d\n", ip->ip_p);
                    continue;
                }

                // Get the message header to check sequence
                struct message_header* msg = (struct message_header*)((char*)&recv_packet + sizeof(struct ipheader));
                uint16_t recv_sequence = ntohs(msg->sequence);

                // Check if this is a server response (should have server sequence)
                if (!is_server_sequence(recv_sequence)) {
                    printf("Ignoring non-server message (sequence: %d)\n", recv_sequence);
                    continue;
                }

                // Check if this matches our sent sequence
                if (get_base_sequence(recv_sequence) != get_base_sequence(sent_sequence)) {
                    printf("Ignoring response with wrong sequence (got: %d, expected: %d)\n", 
                           get_base_sequence(recv_sequence), get_base_sequence(sent_sequence));
                    continue;
                }

                // Ensure we have enough data for message header
                if (packet_len < (sizeof(struct ipheader) + sizeof(struct message_header))) {
                    printf("Packet too small for message header\n");
                    continue;
                }

                // Create a properly aligned packet
                struct custom_packet aligned_packet;
                memset(&aligned_packet, 0, sizeof(aligned_packet));

                // Copy the IP header
                memcpy(&aligned_packet.ip, &recv_packet, sizeof(struct ipheader));

                // Calculate offsets carefully
                char* msg_start = ((char*)&recv_packet) + sizeof(struct ipheader);
                size_t payload_offset = sizeof(struct ipheader) + sizeof(struct message_header);
                size_t payload_size = packet_len - payload_offset;

                // Copy the message header
                memcpy(&aligned_packet.msg_header, msg_start, sizeof(struct message_header));

                // Copy payload if present
                if (payload_size > 0 && payload_size <= sizeof(aligned_packet.payload)) {
                    memcpy(aligned_packet.payload, ((char*)&recv_packet) + payload_offset, payload_size);
                }

                // Debug print raw bytes of message header
                printf("\n========== RESPONSE HEADER ==========\n");
                printf("Raw header bytes: ");
                unsigned char* header_bytes = (unsigned char*)&aligned_packet.msg_header;
                for (size_t i = 0; i < sizeof(struct message_header); i++) {
                    printf("%02X ", header_bytes[i]);
                }
                printf("\nMagic number: 0x%08X\n", ntohl(aligned_packet.msg_header.magic));
                printf("Sequence number: %d\n", ntohs(aligned_packet.msg_header.sequence));
                printf("Payload length: %d\n", ntohl(aligned_packet.msg_header.payload_length));
                printf("====================================\n\n");

                handle_response(&aligned_packet, &source);
                break;  // We got our echo, we can exit
            } else {
                printf("Ignoring packet from unexpected source: %s\n", 
                       inet_ntoa(source.sin_addr));
            }
        }
    }

    if (timeout_occurred) {
        printf("Timeout waiting for server echo\n");
    }

    close(send_sock);
    close(recv_sock);
    return 0;
} 