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
#include <queue>
#include <netinet/ip.h>
#include <net/if.h>
#include <time.h>
#include "raw_socket_common.h"

// Global flag for graceful shutdown
volatile sig_atomic_t keep_running = 1;

// Structure to hold outgoing messages
struct outgoing_message {
    struct {
        struct message_header header;
        char payload[MAX_PAYLOAD_SIZE];
    } packet;
    struct sockaddr_in dest_addr;
    size_t total_length;    // Total message length
    size_t bytes_sent;      // Number of bytes sent so far

    outgoing_message() : total_length(0), bytes_sent(0) {}
};

// Queue for outgoing messages
std::queue<outgoing_message> send_queue;

// Track our last sent sequence number to identify our own packets
uint16_t last_sent_sequence = 0;

// Forward declarations
void queue_response(const struct sockaddr_in *dest, uint16_t sequence, 
                   const char *payload, size_t payload_len);

void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\nShutdown signal received. Cleaning up...\n");
        keep_running = 0;
    }
}

void print_usage(const char* program_name) {
    printf("Usage: %s [-i <interface>]\n", program_name);
    printf("Options:\n");
    printf("  -i <interface>   Network interface to listen on (optional, listens on all interfaces if not specified)\n");
    printf("  -h              Show this help message\n");
}

// Process outgoing messages
bool process_send_queue(int sock) {
    while (!send_queue.empty()) {
        outgoing_message& msg = send_queue.front();
        
        // Calculate remaining bytes to send
        size_t remaining = msg.total_length - msg.bytes_sent;
        if (remaining == 0) {
            send_queue.pop();
            continue;
        }

        // Print debug info before sending
        printf("\n========== SENDING PACKET ==========\n");
        printf("Destination: %s\n", inet_ntoa(msg.dest_addr.sin_addr));
        printf("Total packet length: %zu bytes\n", msg.total_length);
        printf("Message Header:\n");
        printf("  Magic Number: 0x%08X\n", ntohl(msg.packet.header.magic));
        printf("  Sequence: %d\n", ntohs(msg.packet.header.sequence));
        printf("  Payload Length: %d\n", ntohl(msg.packet.header.payload_length));
        printf("Payload: %.*s\n", (int)ntohl(msg.packet.header.payload_length), msg.packet.payload);
        printf("===================================\n\n");

        // Try to send the packet
        ssize_t sent = sendto(sock, 
                            reinterpret_cast<const char*>(&msg.packet) + msg.bytes_sent,
                            remaining, 0,
                            (struct sockaddr*)&msg.dest_addr, 
                            sizeof(msg.dest_addr));
        
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                printf("System buffers full, will retry later\n");
                return false;
            } else if (errno == EMSGSIZE) {
                printf("Message too large for network device\n");
                send_queue.pop();
                continue;
            }
            printf("Send failed: %s (errno: %d)\n", strerror(errno), errno);
            send_queue.pop();
            continue;
        }

        msg.bytes_sent += sent;
        
        if (sent < (ssize_t)remaining) {
            printf("Partial send (%zd of %zu bytes), will continue later\n", 
                   sent, remaining);
            return false;
        }

        printf("Message fully sent (%zu bytes)\n", msg.total_length);
        send_queue.pop();
    }
    return true;
}

// Queue a response packet
void queue_response(const struct sockaddr_in *dest, uint16_t sequence, 
                   const char *payload, size_t payload_len) {
    struct outgoing_message msg;
    memset(&msg.packet, 0, sizeof(msg.packet));

    // Store sequence number
    last_sent_sequence = sequence;

    // Set up message header with server sequence
    msg.packet.header.magic = htonl(MAGIC_NUMBER);
    msg.packet.header.sequence = htons(make_server_sequence(sequence));
    msg.packet.header.payload_length = htonl(payload_len);

    // Copy payload if present
    if (payload && payload_len > 0) {
        memcpy(msg.packet.payload, payload, payload_len);
    }

    // Set message properties
    msg.dest_addr = *dest;
    msg.total_length = sizeof(struct message_header) + payload_len;
    msg.bytes_sent = 0;

    // Add to send queue
    send_queue.push(msg);
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

    // Set up signal handling
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    // Create socket for our custom protocol
    int sock = socket(AF_INET, SOCK_RAW, PROTOCOL_NUM);
    if (sock < 0) {
        perror("Socket creation error");
        exit(1);
    }

    // Print socket settings
    print_socket_settings(sock);

    // Set socket to non-blocking mode
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    // Setup for receiving packets
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;

    if (interface_name != NULL) {
        const char* ip = get_interface_ip(interface_name);
        if (ip == NULL) {
            printf("Error: Could not find IP address for interface %s\n", interface_name);
            close(sock);
            exit(1);
        }
        server_addr.sin_addr.s_addr = inet_addr(ip);
        printf("Listening on interface %s (IP: %s)\n", interface_name, ip);
    } else {
        server_addr.sin_addr.s_addr = INADDR_ANY;
        printf("Listening on all interfaces\n");
    }

    if (bind(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sock);
        exit(1);
    }

    printf("Server started with protocol number %d\n", PROTOCOL_NUM);
    printf("Press Ctrl+C to stop the server\n");

    // Set up poll structure
    struct pollfd pfd;
    pfd.fd = sock;
    pfd.events = POLLIN | POLLOUT;

    // Event loop
    while (keep_running) {
        int ready = poll(&pfd, 1, 1000);
        
        if (ready < 0) {
            if (errno == EINTR) continue;
            perror("poll error");
            break;
        }
        
        if (ready == 0) continue;

        // Handle incoming data
        if (pfd.revents & POLLIN) {
            char recv_buffer[PACKET_SIZE];
            struct sockaddr_in source;
            socklen_t source_len = sizeof(source);

            ssize_t packet_len = recvfrom(sock, recv_buffer, sizeof(recv_buffer), 0,
                                        (struct sockaddr *)&source, &source_len);
            
            if (packet_len < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;
                }
                perror("Error receiving packet");
                continue;
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

            // Get sequence number and check if it's a client message
            uint16_t sequence = ntohs(aligned_packet.msg_header.sequence);
            if (!is_client_sequence(sequence)) {
                printf("Ignoring non-client message (sequence: %d)\n", sequence);
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

            // Echo the message back with a prefix
            const char* prefix = "Echo from server: ";
            size_t prefix_len = strlen(prefix);
            size_t total_len = prefix_len + payload_length;
            
            if (total_len > MAX_PAYLOAD_SIZE) {
                printf("Warning: Response would exceed maximum payload size, truncating\n");
                total_len = MAX_PAYLOAD_SIZE;
            }
            
            char response[MAX_PAYLOAD_SIZE];
            memcpy(response, prefix, prefix_len);
            memcpy(response + prefix_len, aligned_packet.payload, 
                   total_len - prefix_len);
            
            queue_response(&source, sequence, response, total_len);
        }

        // Handle outgoing data
        if (pfd.revents & POLLOUT && !send_queue.empty()) {
            if (!process_send_queue(sock)) {
                continue;
            }
        }

        // Check for errors
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            printf("Socket error detected\n");
            break;
        }
    }

    printf("Server shutting down...\n");
    close(sock);
    return 0;
} 