#include "client.h"
#include "raw_socket_common.h"
#include <unistd.h>

client::client() {
    // Create sending socket with our custom protocol
    m_send_socket = socket(AF_INET, SOCK_RAW, PROTOCOL_NUM);
    if (m_send_socket < 0) {
        perror("Send socket creation error");
        exit(1);
    }

    // Create receiving socket for our custom protocol
    m_recv_socket = socket(AF_INET, SOCK_RAW, PROTOCOL_NUM);
    if (m_recv_socket < 0) {
        perror("Receive socket creation error");
        close(m_send_socket);
        exit(1);
    }

    // Set receive socket to non-blocking mode
    int flags = fcntl(m_recv_socket, F_GETFL, 0);
    fcntl(m_recv_socket, F_SETFL, flags | O_NONBLOCK);
}

client::~client() {
    // Cleanup resources
}

void client::send_message(const std::string& dest_ip, const std::string& message) {
    // Prepare the packet - now only message header and payload
    custom_packet packet;
    int message_len = message.length();

    if (message_len > sizeof(packet.payload)) {
        throw std::runtime_error("Message too long (max " + std::to_string(sizeof(packet.payload)) + " bytes)");
    }   

    // Clear the packet buffer
    memset(&packet, 0, sizeof(packet));

    // Fill in the message header
    packet.msg_header.src_pid = getpid();  // Get current process ID and convert to network byte order
    packet.msg_header.dst_pid = 0; // it means anyone can receive this packet
    packet.msg_header.payload_length = message_len;

    // Add payload
    strncpy(packet.payload, message.c_str(), message_len);

    // Set up destination address
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(dest_ip.c_str());

    // Send the packet
    if (sendto(m_send_socket, &packet, sizeof(struct message_header) + message_len, 0, 
               (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        throw std::runtime_error("Send failed: " + std::string(strerror(errno)));
    }
}

std::string client::receive_response() {
    // Implement response receiving logic
    // Wait for response with timeout
    struct pollfd pfd;
    pfd.fd = m_recv_socket;
    pfd.events = POLLIN;

    while (true) {
        int ret = poll(&pfd, 1, 100);  // Poll every 100ms
        if (ret < 0) {
            if (errno == EINTR) continue;  // Interrupted by signal
            throw std::runtime_error("Poll error: " + std::string(strerror(errno)));
        }
        if (ret > 0 && (pfd.revents & POLLIN)) {
            char recv_buffer[2048]; // actually max packet size is 1500 bytes;
            struct sockaddr_in source;
            socklen_t source_len = sizeof(source);

            ssize_t packet_len = recvfrom(m_recv_socket, recv_buffer, sizeof(recv_buffer), 0,
                                        (struct sockaddr *)&source, &source_len);
            
            if (packet_len < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;  // No data available
                }
                throw std::runtime_error("Receive error: " + std::string(strerror(errno)));
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
            memcpy(&aligned_packet.msg_header, data, sizeof(message_header));

            if (aligned_packet.msg_header.dst_pid != getpid()) {
                printf("Not my message, skipped. Destination is %d, I am %d\n", aligned_packet.msg_header.dst_pid, getpid());
                continue;
            }

            // Get payload length and validate
            uint32_t payload_length = aligned_packet.msg_header.payload_length;
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
            printf("  Payload Length: %u\n", payload_length);
            if (payload_length > 0) {
                printf("Payload: %.*s\n", payload_length, aligned_packet.payload);
            }
            printf("===================================\n\n");

            std::string response(aligned_packet.payload, payload_length);
            return response;
        }
    }
    return {};
}

#include <iostream>

int main() {
    client c;
    c.send_message("127.0.0.1", "Hello, server!");
    std::string response = c.receive_response();
    std::cout << "Response: " << response << std::endl;
    return 0;
}