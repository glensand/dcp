#include "server.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <iostream>

server::server() {
    // Initialize server
}

server::~server() {
    // Cleanup resources
    stop();
}

void server::start() {
    // Create socket for our custom protocol
    m_socket = socket(AF_INET, SOCK_RAW, PROTOCOL_NUM);
    if (m_socket < 0) {
        perror("Socket creation error");
        exit(1);
    }

    // Print socket settings
    print_socket_settings(m_socket);

    // Set socket to non-blocking mode
    int flags = fcntl(m_socket, F_GETFL, 0);
    fcntl(m_socket, F_SETFL, flags | O_NONBLOCK);

    // Setup for receiving packets
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;

    if (bind(m_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(m_socket);
        exit(1);
    }

    printf("Server started with protocol number %d\n", PROTOCOL_NUM);
    printf("Press Ctrl+C to stop the server\n");

    m_running = true;
    m_worker = std::thread([this]() {
        while (m_running) {
            try {
                process();
            } catch (const std::exception& e) {
                std::cout << "Error: " << e.what() << std::endl;
            } catch (...) {
                std::cout << "Unknown error occurred" << std::endl;
            }
        }
    });
}

void server::stop() {
    m_running = false;
    m_worker.join();
}

void server::process() {
    // Set up poll structure
    struct pollfd pfd;
    pfd.fd = m_socket;
    pfd.events = POLLIN | POLLOUT;

    int ready = poll(&pfd, 1, 1000);
    
    if (ready < 0) {
        if (errno != EINTR) {
            throw std::runtime_error("poll error");
        }
    }
    
    if (ready != 0){
        // Handle incoming data
        if (pfd.revents & POLLIN) {
            char recv_buffer[2048];
            struct sockaddr_in source;
            socklen_t source_len = sizeof(source);
            ssize_t packet_len = recvfrom(m_socket, recv_buffer, sizeof(recv_buffer), 0,
                                        (struct sockaddr *)&source, &source_len);
            if (packet_len < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                    
                }
                perror("Error receiving packet");
            }
            else {

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
            if (data_len < sizeof(message_header)) {
                throw std::runtime_error("Packet too small for message header");
            }
            // Create a properly aligned packet
            auto* header = (message_header*)data;
            // Get payload length and validate
            uint32_t payload_length = header->payload_length;
            if (payload_length > sizeof(recv_buffer)) {
                throw std::runtime_error("Invalid payload length: " + std::to_string(payload_length));
            }
            if (header->src_pid == getpid() || (header->dst_pid != getpid() && header->dst_pid != 0)) {
                printf("Not my message, skipped. Destination is %d, I am %d\n", header->dst_pid, getpid());
                return;
            }
            char* payload = data + sizeof(message_header);
            // Print received message details
            printf("Message Header:\n");
            printf("  Src PID: %d\n", header->src_pid);
            printf("  Dst PID: %d\n", header->dst_pid);
            printf("  Payload Length: %u\n", payload_length);
            if (payload_length > 0) {
                printf("Payload: %.*s\n", payload_length, payload);
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
            memcpy(response + prefix_len, payload, payload_length);

            queue_response(&source, header->src_pid, response, total_len);
        }
        // Handle outgoing data
        if (pfd.revents & POLLOUT && !send_queue.empty()) {
            if (!process_send_queue()) {
                // TODO:: log error
            }
        }
        // Check for errors
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            // TODO implement custom exception to handle it properly
            throw std::runtime_error("Socket error detected");
        }
    }
}

// Process outgoing messages
bool server::process_send_queue() {
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
        printf("===================================\n\n");

        // Try to send the packet
        ssize_t sent = sendto(m_socket, 
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

void server::queue_response(const struct sockaddr_in *dest, uint16_t dst_pid, 
                            const char *payload, size_t payload_len) {
    struct outgoing_message msg;
    memset(&msg.packet, 0, sizeof(msg.packet));

    // Set up message header with server sequence
    msg.packet.msg_header.src_pid = getpid();
    msg.packet.msg_header.dst_pid = dst_pid;
    msg.packet.msg_header.payload_length = payload_len;

    // Copy payload if present
    if (payload && payload_len > 0) {
        memcpy(msg.packet.payload, payload, payload_len);
    }

    // Set message properties
    msg.dest_addr = *dest;
    msg.total_length = sizeof(message_header) + payload_len;
    msg.bytes_sent = 0;

    // Add to send queue
    send_queue.push(msg);
}

server s;

void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\nShutdown signal received. Cleaning up...\n");
        s.stop();
    }
}

int main() {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    s.start();

    while (s.is_running()) {
        sleep(1);
    }

    return 0;
}