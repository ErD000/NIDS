#ifndef NETWORK_STRUCTURES_H
#define NETWORK_STRUCTURES_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdint>

// Structure for IP headers on Windows
typedef struct iphdr {
    unsigned int ihl : 4;       // IP header length
    unsigned int version : 4;   // version
    unsigned char tos;          // type of service
    unsigned short tot_len;     // total length
    unsigned short id;          // unique identifier
    unsigned short frag_off;    // fragment offset
    unsigned char ttl;          // time to live
    unsigned char protocol;     // protocol
    unsigned short check;       // checksum
    struct in_addr saddr;       // source address
    struct in_addr daddr;       // destination address
} IPHDR, * PIPHDR;

typedef struct tcphdr {
    uint8_t  flags;
    uint16_t source;            // Source port
    uint16_t dest;              // Destination port
    uint32_t seq;               // Sequence number
    uint32_t ack_seq;           // Acknowledgment number
    uint16_t res1 : 4;          // 4 reserved bits
    uint16_t doff : 4;          // TCP header length (data offset)
    uint16_t fin : 1;           // FIN flag
    uint16_t syn : 1;           // SYN flag
    uint16_t rst : 1;           // RST flag
    uint16_t psh : 1;           // PSH flag
    uint16_t ack : 1;           // ACK flag
    uint16_t urg : 1;           // URG flag
    uint16_t res2 : 2;          // 2 reserved bits
    uint16_t window;            // Window size
    uint16_t check;             // Checksum
    uint16_t urg_ptr;           // Urgent pointer
} TCPHDR, * PTCPHDR;

// TCP Flag Definitions
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20

#endif // NETWORK_STRUCTURES_H
