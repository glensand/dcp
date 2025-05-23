# Raw Socket Communication with XOR Encryption

This project implements a simple raw socket communication system using XOR-based encryption. It consists of a client and server that can exchange encrypted messages over raw IP sockets.

## Features

- Custom protocol over raw IP sockets
- XOR-based encryption with a 32-byte key
- Random salt generation for each message
- Sequence number tracking
- Interface selection support
- No external dependencies

## Prerequisites

- CMake 3.10 or higher
- C++11 compatible compiler

## Building

1. Create a build directory and navigate to it:
```bash
mkdir build
cd build
```

2. Configure and build the project:
```bash
cmake ..
make
```

This will create three executables:
- `generate_key_xor`: Utility to generate key files
- `raw_socket_client_xor`: Client program for sending encrypted messages
- `raw_socket_server_xor`: Server program for receiving encrypted messages

## Usage

### 1. Generate an XOR Key

First, generate a key file that will be used by both the client and server:

```bash
sudo ./generate_key_xor xor.key
```

The key file must be accessible by both the client and server.

### 2. Start the Server

The server can listen on all interfaces or a specific one:

```bash
# Listen on all interfaces
sudo ./raw_socket_server_xor -k xor.key

# Listen on a specific interface (e.g., en0)
sudo ./raw_socket_server_xor -k xor.key -i en0
```

### 3. Send Messages from the Client

The client requires a destination IP address and message:

```bash
sudo ./raw_socket_client_xor -d <destination_ip> -m "Your secret message" -k xor.key
```

## Security Notes

1. The XOR encryption used in this project is a simple demonstration and not cryptographically secure.
2. Each message uses a random salt to provide some basic protection against replay attacks.
3. The key file should be kept secure and only accessible by authorized users.
4. Raw sockets require root privileges (sudo).

## Protocol Details

- Custom protocol number: 200
- Magic number: 0x1234ABCD
- XOR key size: 32 bytes
- Salt size: 8 bytes
- Message types:
  - HELLO (1)
  - DATA (2)
  - ACK (3)
  - GOODBYE (4)

## Example Usage

1. Generate a key:
```bash
sudo ./generate_key_xor xor.key
```

2. Start the server in one terminal:
```bash
sudo ./raw_socket_server_xor -k xor.key
```

3. Send an encrypted message from another terminal:
```bash
sudo ./raw_socket_client_xor -d 127.0.0.1 -m "Hello, encrypted world!" -k xor.key
```

## How the XOR Encryption Works

1. Each message is encrypted using both a static key and a random salt:
   - The static key is a 32-byte value stored in the key file
   - The salt is 8 random bytes generated for each message

2. The encryption process:
   - First XOR the message with the salt (repeated if needed)
   - Then XOR the result with the key (repeated if needed)

3. The decryption process is identical since XOR is its own inverse:
   - XOR with the salt
   - XOR with the key
   - The original message is recovered

This provides a basic level of message privacy and some protection against replay attacks, though it should not be used for sensitive data in production environments.