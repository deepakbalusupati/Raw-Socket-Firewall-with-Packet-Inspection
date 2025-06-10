#include "../include/firewall.h"
#include <cstring>
#include <fstream>
#include <iostream>
#include <net/ethernet.h>
#include <net/if.h>
#include <sstream>
#include <sys/ioctl.h>

Firewall::Firewall() : pcapHandle(nullptr), running(false) {}

Firewall::~Firewall() {
  stop();
  if (pcapHandle) {
    pcap_close(pcapHandle);
  }
}

std::vector<std::string> Firewall::getAvailableInterfaces() {
  std::vector<std::string> interfaces;
  char errbuf[PCAP_ERRBUF_SIZE];

#ifdef _WIN32
  // Windows implementation
  pcap_if_t *alldevs;
  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
    return interfaces;
  }

  for (pcap_if_t *dev = alldevs; dev != NULL; dev = dev->next) {
    interfaces.push_back(dev->name);
  }

  pcap_freealldevs(alldevs);
#else
  // Linux implementation
  struct ifaddrs *ifaddr, *ifa;

  if (getifaddrs(&ifaddr) == -1) {
    return interfaces;
  }

  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_PACKET)
      continue;

    interfaces.push_back(ifa->ifa_name);
  }

  freeifaddrs(ifaddr);
#endif

  return interfaces;
}

bool Firewall::init(const std::string &interface) {
  char errbuf[PCAP_ERRBUF_SIZE];

  if (interface.empty()) {
    auto interfaces = getAvailableInterfaces();
    if (interfaces.empty()) {
      std::cerr << "No network interfaces found!" << std::endl;
      return false;
    }

    // Try to find a non-loopback interface
    for (const auto &iface : interfaces) {
      if (iface != "lo") {
        this->interface = iface;
        break;
      }
    }

    if (this->interface.empty()) {
      this->interface = interfaces[0];
    }

    std::cout << "Using network interface: " << this->interface << std::endl;
  } else {
    this->interface = interface;
  }

#ifdef _WIN32
  // Initialize WinSock for Windows
  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
    std::cerr << "Failed to initialize WinSock" << std::endl;
    return false;
  }
#endif

  pcapHandle = pcap_open_live(this->interface.c_str(), BUFSIZ, 1, 1000, errbuf);
  if (!pcapHandle) {
    std::cerr << "Error opening interface " << this->interface << ": " << errbuf
              << std::endl;

    // Show available interfaces
    auto interfaces = getAvailableInterfaces();
    if (!interfaces.empty()) {
      std::cerr << "Available interfaces:" << std::endl;
      for (const auto &iface : interfaces) {
        std::cerr << "  - " << iface << std::endl;
      }
    }

    return false;
  }

  if (pcap_datalink(pcapHandle) != DLT_EN10MB) {
    std::cerr << "Interface "
              << this->interface << " doesn't provide Ethernet headers"
              << std::endl;
    return false;
  }

  return true;
}

void Firewall::start() {
  if (!pcapHandle || running)
    return;

  running = true;
  std::cout << "Firewall started on interface " << interface << std::endl;
  pcap_loop(pcapHandle, 0, Firewall::packetHandler,
            reinterpret_cast<u_char *>(this));
}

void Firewall::stop() {
  running = false;
  if (pcapHandle) {
    pcap_breakloop(pcapHandle);
  }
  std::cout << "Firewall stopped" << std::endl;

#ifdef _WIN32
  // Cleanup WinSock
  WSACleanup();
#endif
}

void Firewall::loadRules(const std::string &ruleFile) {
  std::ifstream file(ruleFile);
  if (!file.is_open()) {
    std::cerr << "Failed to open rules file: " << ruleFile << std::endl;
    return;
  }

  rules.clear();
  std::string line;
  while (std::getline(file, line)) {
    if (!line.empty() && line[0] != '#') {
      rules.push_back(line);
    }
  }
  std::cout << "Loaded " << rules.size() << " firewall rules" << std::endl;
}

void Firewall::addToBlacklist(const std::string &ip) {
  blacklist.insert(ip);
  std::cout << "Added to blacklist: " << ip << std::endl;
}

void Firewall::addToWhitelist(const std::string &ip) {
  whitelist.insert(ip);
  std::cout << "Added to whitelist: " << ip << std::endl;
}

void Firewall::packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr,
                             const u_char *packet) {
  Firewall *firewall = reinterpret_cast<Firewall *>(userData);
  firewall->processPacket(packet, pkthdr);
}

void Firewall::processPacket(const u_char *packet,
                             const struct pcap_pkthdr *header) {
  struct ethhdr *ethHeader = (struct ethhdr *)packet;

  if (ntohs(ethHeader->h_proto) != ETH_P_IP) {
    return; // Not an IP packet
  }

  struct ip *ipHeader = (struct ip *)(packet + sizeof(struct ethhdr));
  struct tcphdr *tcpHeader = nullptr;
  struct udphdr *udpHeader = nullptr;

  if (ipHeader->ip_p == IPPROTO_TCP) {
    tcpHeader = (struct tcphdr *)(packet + sizeof(struct ethhdr) +
                                  (ipHeader->ip_hl << 2));
  } else if (ipHeader->ip_p == IPPROTO_UDP) {
    udpHeader = (struct udphdr *)(packet + sizeof(struct ethhdr) +
                                  (ipHeader->ip_hl << 2));
  }

  if (!isAllowed(ipHeader, tcpHeader, udpHeader)) {
    char srcIp[INET_ADDRSTRLEN];
    char dstIp[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipHeader->ip_src), srcIp, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIp, INET_ADDRSTRLEN);

    std::cout << "Blocked packet: " << srcIp << " -> " << dstIp;
    if (tcpHeader) {
      std::cout << " TCP port " << ntohs(tcpHeader->th_dport);
    } else if (udpHeader) {
      std::cout << " UDP port " << ntohs(udpHeader->uh_dport);
    }
    std::cout << std::endl;
  }
}

bool Firewall::isAllowed(const struct ip *ipHeader,
                         const struct tcphdr *tcpHeader,
                         const struct udphdr *udpHeader) {
  char srcIp[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(ipHeader->ip_src), srcIp, INET_ADDRSTRLEN);

  // Check whitelist first
  if (whitelist.find(srcIp) != whitelist.end()) {
    return true;
  }

  // Check blacklist
  if (blacklist.find(srcIp) != blacklist.end()) {
    return false;
  }

  // Check rules
  for (const auto &rule : rules) {
    std::istringstream iss(rule);
    std::string action, protocol, ruleSrcIp, ruleDstIp;
    int port = 0;

    iss >> action >> protocol >> ruleSrcIp >> ruleDstIp >> port;

    char dstIp[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIp, INET_ADDRSTRLEN);

    if ((ruleSrcIp == "*" || ruleSrcIp == srcIp) &&
        (ruleDstIp == "*" || ruleDstIp == dstIp)) {

      if ((protocol == "tcp" && ipHeader->ip_p == IPPROTO_TCP) ||
          (protocol == "udp" && ipHeader->ip_p == IPPROTO_UDP) ||
          (protocol == "*")) {

        if (port == 0 || (tcpHeader && ntohs(tcpHeader->th_dport) == port) ||
            (udpHeader && ntohs(udpHeader->uh_dport) == port)) {

          return action == "allow";
        }
      }
    }
  }

  // Default deny
  return false;
}