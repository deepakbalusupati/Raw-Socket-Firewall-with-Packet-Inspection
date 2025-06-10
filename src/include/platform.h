#ifndef PLATFORM_H
#define PLATFORM_H

// Common for both platforms first (to avoid ordering issues)
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>


// Platform-specific includes and definitions
#ifdef _WIN32
// Windows-specific
#define WIN32_LEAN_AND_MEAN
#include <iphlpapi.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wpcap.lib")

// Typedef to make Windows code compatible with Linux code
typedef struct ip_header {
  unsigned char ip_hl : 4,       // Header length
      ip_v : 4;                  // Version
  unsigned char ip_tos;          // Type of service
  short ip_len;                  // Total length
  unsigned short ip_id;          // Identification
  short ip_off;                  // Fragment offset field
  unsigned char ip_ttl;          // Time to live
  unsigned char ip_p;            // Protocol
  unsigned short ip_sum;         // Checksum
  struct in_addr ip_src, ip_dst; // Source and dest address
} ip;

typedef struct tcp_header {
  unsigned short th_sport; // Source port
  unsigned short th_dport; // Destination port
  unsigned int th_seq;     // Sequence number
  unsigned int th_ack;     // Acknowledgement number
  unsigned char th_x2 : 4, // (unused)
      th_off : 4;          // Data offset
  unsigned char th_flags;  // Control flags
  unsigned short th_win;   // Window
  unsigned short th_sum;   // Checksum
  unsigned short th_urp;   // Urgent pointer
} tcphdr;

typedef struct udp_header {
  unsigned short uh_sport; // Source port
  unsigned short uh_dport; // Destination port
  unsigned short uh_ulen;  // UDP length
  unsigned short uh_sum;   // UDP checksum
} udphdr;

// Ethernet header (simplified)
typedef struct eth_header {
  unsigned char h_dest[6];   // Destination host address
  unsigned char h_source[6]; // Source host address
  unsigned short h_proto;    // Protocol type
} ethhdr;

// Definitions to match Linux
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define INET_ADDRSTRLEN 16

#else
// Linux-specific
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>

#endif

// Common for both platforms
#include <pcap.h>

#endif // PLATFORM_H