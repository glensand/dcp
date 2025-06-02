#pragma once

#include <string>
#include <thread>
#include <queue>
#include <atomic>

#include "raw_socket_common.h"

class server final {
public:
    server();
    ~server();

    void start();
    void stop();
    
    bool is_running() const { return m_running; }

private:
    void process();
    void queue_response(const struct sockaddr_in *dest, uint16_t dst_pid, 
                        const char *payload, size_t payload_len);
    bool process_send_queue();

    std::thread m_worker;
    std::atomic<bool> m_running;

    int m_socket = -1;

    // Structure to hold outgoing messages
    struct outgoing_message {
        custom_packet packet;
        struct sockaddr_in dest_addr;
        size_t total_length;    // Total message length
        size_t bytes_sent;      // Number of bytes sent so far

        outgoing_message() : total_length(0), bytes_sent(0) {}
    };

    // Queue for outgoing messages
    std::queue<outgoing_message> send_queue;
};
