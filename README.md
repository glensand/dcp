# Raw Socket Communication System

This project implements a simple client-server communication system using raw sockets. It demonstrates how to create a custom protocol on top of IP, with proper packet handling and sequence number tracking.

## Features

- Custom protocol implementation over raw sockets
- Sequence number tracking for client/server messages
- Non-blocking socket operations
- Timeout handling
- Interface selection support
- Detailed debug output
- Clean protocol layering (OS handles IP, we handle application layer)

## Protocol Details

### Protocol Structure
- Protocol Number: 200 (custom protocol number)
- Magic Number: 0x1234ABCD (for packet validation)
- Maximum Payload Size: 1024 bytes

### Message Format
```
Message Header:
  - Magic Number (4 bytes)
  - Sequence Number (2 bytes)
  - Payload Length (4 bytes)

Payload:
  - Variable length data (up to 1024 bytes)
```

### Sequence Numbers
- Client messages: High bit clear (0x0000 - 0x7FFF)
- Server messages: High bit set (0x8000 - 0xFFFF)
- Base sequence number preserved for matching requests/responses

## Building

```bash
# Compile the client
g++ -o raw_socket_client raw_socket_client_new.cpp -std=c++11

# Compile the server
g++ -o raw_socket_server raw_socket_server_new.cpp -std=c++11
```

## Usage

### Starting the Server
```bash
# Listen on all interfaces
sudo ./raw_socket_server

# Listen on a specific interface
sudo ./raw_socket_server -i eth0
```

### Running the Client
```bash
# Send a message
sudo ./raw_socket_client -d <destination_ip> -m "Your message"
```

### Command Line Options

Server:
- `-i <interface>`: Network interface to listen on (optional)
- `-h`: Show help message

Client:
- `-d <dest_ip>`: Destination IP address (required)
- `-m <message>`: Message to send (required)
- `-h`: Show help message

## Implementation Notes

1. Raw Socket Creation
   - Uses protocol number 200 for both sending and receiving
   - Non-blocking mode for efficient I/O

2. Packet Processing
   - IP headers handled by OS
   - Application protocol starts after IP header
   - Proper header alignment and payload handling

3. Security Features
   - Magic number validation
   - Sequence number tracking
   - Payload length validation

4. Error Handling
   - Timeout for client responses
   - Graceful server shutdown
   - Comprehensive error checking
   - Detailed debug output

## Requirements

- Linux/Unix-based system with raw socket support
- Root privileges (for raw socket operations)
- C++11 compatible compiler

## Security Notes

1. Raw sockets require root privileges
2. This is a demonstration project and should not be used in production without additional security measures
3. No encryption is implemented - data is sent in clear text
4. Consider adding authentication and encryption for production use

## Debugging

The system provides detailed debug output including:
- Packet structure and contents
- IP header information
- Sequence numbers
- Magic number validation
- Payload contents
- Error conditions

## Known Limitations

1. Maximum payload size of 1024 bytes
2. Requires root privileges
3. No retransmission mechanism
4. No connection state tracking
5. No encryption or authentication