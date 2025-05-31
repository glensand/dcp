#pragma once

#include <string>

class client final {
public:
    client();
    ~client();

    void send_message(const std::string& dest_ip, const std::string& message);
    std::string receive_response();
    
private:
    int m_send_socket = -1;
    int m_recv_socket = -1;

    uint16_t sent_sequence = 0;
};