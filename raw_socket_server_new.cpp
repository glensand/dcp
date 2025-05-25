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

// Track our last sent sequence number and destination to identify our own packets
struct last_sent_info {
    uint16_t sequence;
    in_addr_t dest_ip;
} last_sent;

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

// Handle received message
void handle_message(const struct custom_packet *packet, const struct sockaddr_in *source) {
    // Print debug info for all received packets
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

    // Print message details
    printf("\nReceived message from %s\n", inet_ntoa(source->sin_addr));
    printf("Sequence: %d\n", sequence);
    printf("Payload length: %d\n", payload_length);
    printf("Payload: %.*s\n", payload_length, packet->payload);

    // Echo the message back
    const char* prefix = "Response from server: ";
    size_t prefix_len = strlen(prefix);
    size_t total_len = prefix_len + payload_length;
    
    // Ensure we don't exceed maximum payload size
    if (total_len > MAX_PAYLOAD_SIZE) {
        printf("Warning: Response would exceed maximum payload size, truncating\n");
        total_len = MAX_PAYLOAD_SIZE;
    }
    
    // Create the combined response
    char response[MAX_PAYLOAD_SIZE];
    memcpy(response, prefix, prefix_len);
    memcpy(response + prefix_len, packet->payload, 
           total_len - prefix_len);  // This will automatically truncate if needed
    
    queue_response(source, sequence, response, total_len);
    printf("\n========== QUEUED RESPONSE ==========\n");
    printf("Echo response queued for %s\n", inet_ntoa(source->sin_addr));
    printf("Sequence: %d\n", sequence);
    printf("Original payload length: %d\n", payload_length);
    printf("Response length with prefix: %zu\n", total_len);
    printf("Full response: %.*s\n", (int)total_len, response);
    printf("==================================\n\n");
}

// Prepare and queue a response packet
void queue_response(const struct sockaddr_in *dest, uint16_t sequence, 
                   const char *payload, size_t payload_len) {
    struct outgoing_message msg;
    memset(&msg.packet, 0, sizeof(msg.packet));

    // Update our last sent info - store the base sequence number
    last_sent.sequence = get_base_sequence(sequence);
    last_sent.dest_ip = dest->sin_addr.s_addr;

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

// Process outgoing messages
bool process_send_queue(int sock) {
    while (!send_queue.empty()) {
        outgoing_message& msg = send_queue.front();
        
        // Calculate remaining bytes to send
        size_t remaining = msg.total_length - msg.bytes_sent;
        if (remaining == 0) {
            // Message was fully sent
            send_queue.pop();
            continue;
        }

        // Try to send the packet
        printf("\n========== SENDING PACKET ==========\n");
        printf("Destination: %s\n", inet_ntoa(msg.dest_addr.sin_addr));
        printf("Packet size: %zu bytes (sending %zu bytes from offset %zu)\n", 
               msg.total_length, remaining, msg.bytes_sent);
        
        // Print the packet content we're about to send
        printf("Packet content being sent:\n");
        printf("Message Header:\n");
        printf("  Magic Number: 0x%08X\n", ntohl(msg.packet.header.magic));
        printf("  Sequence: %d\n", ntohs(msg.packet.header.sequence));
        printf("  Payload Length: %d\n", ntohl(msg.packet.header.payload_length));
        
        // Print hex dump of what we're sending
        printf("Raw bytes being sent (from offset %zu):\n", msg.bytes_sent);
        unsigned char* send_data = (unsigned char*)&msg.packet + msg.bytes_sent;
        for (size_t i = 0; i < remaining; i++) {
            printf("%02X ", send_data[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        printf("\n");
        
        // Print payload as text if we're sending from the start
        if (msg.bytes_sent == 0) {
            size_t payload_len = ntohl(msg.packet.header.payload_length);
            printf("Payload as text: %.*s\n", (int)payload_len, msg.packet.payload);
        }
        printf("==================================\n");

        ssize_t sent = sendto(sock, 
                            reinterpret_cast<const char*>(&msg.packet) + msg.bytes_sent,
                            remaining, 0,
                            (struct sockaddr*)&msg.dest_addr, 
                            sizeof(msg.dest_addr));
        
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // System buffers are full, try again later
                printf("System buffers full, will retry later\n");
                return false;
            } else if (errno == EMSGSIZE) {
                // Message too large for the device MTU
                printf("Message too large for network device\n");
                send_queue.pop(); // Remove problematic message
                continue;
            }
            printf("Send failed: %s (errno: %d)\n", strerror(errno), errno);
            send_queue.pop();
            continue;
        }

        // Update bytes sent
        msg.bytes_sent += sent;
        
        // If this wasn't everything we tried to send, we need to try again later
        if (sent < (ssize_t)remaining) {
            printf("Partial send (%zd of %zu bytes), will continue later\n", 
                   sent, remaining);
            return false;
        }

        // Message was fully sent
        printf("Message fully sent (%zu bytes)\n", msg.total_length);
        send_queue.pop();
    }
    return true;
}

int main(int argc, char *argv[]) {
    char *interface_name = NULL;
    int opt;

    // Initialize random number generator for packet IDs
    srand(time(NULL));

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

    // Create receiving socket for our custom protocol
    int recv_sock = socket(AF_INET, SOCK_RAW, PROTOCOL_NUM);
    if (recv_sock < 0) {
        perror("Receive socket creation error");
        exit(1);
    }

    // Print socket settings before we modify anything
    printf("Initial socket settings:\n");
    print_socket_settings(recv_sock);

    // Set socket to non-blocking mode
    int flags = fcntl(recv_sock, F_GETFL, 0);
    fcntl(recv_sock, F_SETFL, flags | O_NONBLOCK);

    // Print socket settings after modifications
    printf("Socket settings after setting non-blocking mode:\n");
    print_socket_settings(recv_sock);

    // Setup for receiving packets
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
    printf("Press Ctrl+C to stop the server\n");

    // Set up poll structure
    struct pollfd pfd;
    pfd.fd = recv_sock;
    pfd.events = POLLIN | POLLOUT;  // Monitor for both read and write events

    // Event loop using poll
    while (keep_running) {
        // Wait for events with a 1-second timeout (1000ms)
        int ready = poll(&pfd, 1, 1000);
        
        if (ready < 0) {
            if (errno == EINTR) {
                // Interrupted by signal, check if we should continue
                continue;
            }
            perror("poll error");
            break;
        }
        
        if (ready == 0) {
            // Timeout, continue to next iteration
            continue;
        }

        // Handle incoming data
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
                perror("Error receiving packet");
                continue;
            }

            // Print received packet length
            printf("\n========== RECEIVED PACKET ==========\n");
            printf("Total packet length: %zd bytes\n", packet_len);
            printf("From IP: %s\n", inet_ntoa(source.sin_addr));
            
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
            
            printf("Raw packet dump (first 32 bytes):\n");
            unsigned char* raw_packet = (unsigned char*)&recv_packet;
            for (size_t i = 0; i < (packet_len < 32 ? packet_len : 32); i++) {
                printf("%02X ", raw_packet[i]);
                if ((i + 1) % 16 == 0) printf("\n");
            }
            printf("\n==================================\n");
            
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

            // Get the message header from the packet
            struct message_header* msg = (struct message_header*)((char*)&recv_packet + sizeof(struct ipheader));
            
            // Check if this is a client message (should have client sequence)
            uint16_t recv_sequence = ntohs(msg->sequence);
            if (!is_client_sequence(recv_sequence)) {
                printf("Ignoring non-client message (sequence: %d)\n", recv_sequence);
                continue;
            }

            // Only ignore if this matches our last sent packet's sequence AND
            // it's coming from the IP we sent to (meaning it's our echo coming back)
            if (get_base_sequence(recv_sequence) == get_base_sequence(last_sent.sequence) && 
                ip->ip_src.s_addr == last_sent.dest_ip) {
                printf("Ignoring our own echo response (sequence: %d from IP: %s)\n", 
                       get_base_sequence(recv_sequence), inet_ntoa(ip->ip_src));
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
            printf("\n========== MESSAGE HEADER ==========\n");
            printf("Raw header bytes: ");
            unsigned char* header_bytes = (unsigned char*)&aligned_packet.msg_header;
            for (size_t i = 0; i < sizeof(struct message_header); i++) {
                printf("%02X ", header_bytes[i]);
            }
            printf("\nMagic number: 0x%08X\n", ntohl(aligned_packet.msg_header.magic));
            printf("Sequence number: %d\n", ntohs(aligned_packet.msg_header.sequence));
            printf("Payload length: %d\n", ntohl(aligned_packet.msg_header.payload_length));
            printf("==================================\n\n");
            
            handle_message(&aligned_packet, &source);
        }

        // Handle outgoing data
        if (pfd.revents & POLLOUT && !send_queue.empty()) {
            if (!process_send_queue(recv_sock)) {
                // Error or would block, will try again on next iteration
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
    close(recv_sock);
    return 0;
} 