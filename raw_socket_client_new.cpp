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

    // Create sending socket with our custom protocol
    int send_sock = socket(AF_INET, SOCK_RAW, PROTOCOL_NUM);
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

    // Set receive socket to non-blocking mode
    int flags = fcntl(recv_sock, F_GETFL, 0);
    fcntl(recv_sock, F_SETFL, flags | O_NONBLOCK);

    // Prepare the packet - now only message header and payload
    struct custom_packet packet;
    static uint16_t sequence_number = 0;
    int message_len = strlen(message);

    if (message_len > sizeof(packet.payload)) {
        printf("Message too long (max %lu bytes)\n", sizeof(packet.payload));
        close(send_sock);
        close(recv_sock);
        exit(1);
    }

    // Clear the packet buffer
    memset(&packet, 0, sizeof(packet));

    // Fill in the message header
    sent_sequence = sequence_number++;  // Store the sequence number we're sending
    packet.msg_header.magic = htonl(MAGIC_NUMBER);
    packet.msg_header.sequence = htons(make_client_sequence(sent_sequence));
    packet.msg_header.payload_length = htonl(message_len);

    // Add payload
    strncpy(packet.payload, message, sizeof(packet.payload) - 1);

    // Print debug info for the packet we're about to send
    printf("\n========== SENDING PACKET ==========\n");
    printf("Destination: %s\n", dest_ip);
    printf("Total packet length: %zu bytes\n", sizeof(struct message_header) + message_len);
    printf("Message Header:\n");
    printf("  Magic Number: 0x%08X\n", ntohl(packet.msg_header.magic));
    printf("  Sequence: %d\n", ntohs(packet.msg_header.sequence));
    printf("  Payload Length: %d\n", ntohl(packet.msg_header.payload_length));
    printf("Payload: %s\n", message);
    printf("===================================\n\n");

    // Set up destination address
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(dest_ip);

    // Send the packet
    if (sendto(send_sock, &packet, sizeof(struct message_header) + message_len, 0, 
               (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        printf("Send failed: %s (errno: %d)\n", strerror(errno), errno);
        close(send_sock);
        close(recv_sock);
        exit(1);
    }

    printf("Packet sent successfully to %s\n", dest_ip);
    printf("Waiting for server echo...\n");

    // Wait for response with timeout
    struct pollfd pfd;
    pfd.fd = recv_sock;
    pfd.events = POLLIN;
    alarm(5);  // 5 second timeout

    while (!timeout_occurred) {
        int ret = poll(&pfd, 1, 100);  // Poll every 100ms
        if (ret < 0) {
            if (errno == EINTR) continue;  // Interrupted by signal
            perror("Poll error");
            break;
        }
        if (ret > 0 && (pfd.revents & POLLIN)) {
            char recv_buffer[PACKET_SIZE];
            struct sockaddr_in source;
            socklen_t source_len = sizeof(source);

            ssize_t packet_len = recvfrom(recv_sock, recv_buffer, sizeof(recv_buffer), 0,
                                        (struct sockaddr *)&source, &source_len);
            
            if (packet_len < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;  // No data available
                }
                perror("Receive error");
                break;
            }

            printf("\n========== RECEIVED PACKET ==========\n");
            printf("From: %s\n", inet_ntoa(source.sin_addr));
            printf("Total length: %zd bytes\n", packet_len);

            // Skip the IP header in received data
            // The first byte contains version (high 4 bits) and header length (low 4 bits)
            // Header length is in 32-bit words, so multiply by 4 to get bytes
            unsigned char ip_header_length = (recv_buffer[0] & 0x0F) * 4;
            char* data = recv_buffer + ip_header_length;
            ssize_t data_len = packet_len - ip_header_length;

            printf("IP header length: %d bytes\n", ip_header_length);
            printf("Data length: %zd bytes\n", data_len);

            // We need at least a message header
            if (data_len < sizeof(struct message_header)) {
                printf("Packet too small for message header\n");
                continue;
            }

            // Create a properly aligned packet
            struct custom_packet aligned_packet;
            memset(&aligned_packet, 0, sizeof(aligned_packet));

            // Copy the message header
            memcpy(&aligned_packet.msg_header, data, sizeof(struct message_header));

            // Verify magic number
            uint32_t magic = ntohl(aligned_packet.msg_header.magic);
            if (magic != MAGIC_NUMBER) {
                printf("Invalid magic number: 0x%08X\n", magic);
                continue;
            }

            // Get sequence number and check if it's a server response
            uint16_t sequence = ntohs(aligned_packet.msg_header.sequence);
            if (!is_server_sequence(sequence)) {
                printf("Ignoring non-server message (sequence: %d)\n", sequence);
                continue;
            }

            // Check if this matches our sent sequence
            if (get_base_sequence(sequence) != get_base_sequence(sent_sequence)) {
                printf("Ignoring response with wrong sequence (got: %d, expected: %d)\n", 
                       get_base_sequence(sequence), get_base_sequence(sent_sequence));
                continue;
            }

            // Get payload length and validate
            uint32_t payload_length = ntohl(aligned_packet.msg_header.payload_length);
            if (payload_length > sizeof(aligned_packet.payload)) {
                printf("Invalid payload length: %u\n", payload_length);
                continue;
            }

            // Copy payload if present
            if (payload_length > 0) {
                memcpy(aligned_packet.payload, 
                       data + sizeof(struct message_header),
                       payload_length);
            }

            // Print received message details
            printf("Message Header:\n");
            printf("  Magic Number: 0x%08X\n", magic);
            printf("  Sequence: %d\n", sequence);
            printf("  Payload Length: %u\n", payload_length);
            if (payload_length > 0) {
                printf("Payload: %.*s\n", payload_length, aligned_packet.payload);
            }
            printf("===================================\n\n");

            handle_response(&aligned_packet, &source);
            break;  // We got our response, we can exit
        }
    }

    if (timeout_occurred) {
        printf("Timeout waiting for server response\n");
    }

    close(send_sock);
    close(recv_sock);
    return 0;
} 