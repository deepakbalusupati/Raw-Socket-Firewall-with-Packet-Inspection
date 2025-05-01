#include "firewall.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>

Firewall::Firewall() : pcapHandle(nullptr), running(false) {}

Firewall::~Firewall() {
    stop();
    if (pcapHandle) {
        pcap_close(pcapHandle);
    }
}

bool Firewall::init(const std::string& interface) {
    this->interface = interface;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pcapHandle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!pcapHandle) {
        std::cerr << "Error opening interface " << interface << ": " << errbuf << std::endl;
        return false;
    }
    
    if (pcap_datalink(pcapHandle) != DLT_EN10MB) {
        std::cerr << "Interface " << interface << " doesn't provide Ethernet headers" << std::endl;
        return false;
    }
    
    return true;
}

void Firewall::start() {
    if (!pcapHandle || running) return;
    
    running = true;
    pcap_loop(pcapHandle, 0, Firewall::packetHandler, reinterpret_cast<u_char*>(this));
}

void Firewall::stop() {
    running = false;
    if (pcapHandle) {
        pcap_breakloop(pcapHandle);
    }
}

void Firewall::loadRules(const std::string& ruleFile) {
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
}

void Firewall::addToBlacklist(const std::string& ip) {
    blacklist.insert(ip);
}

void Firewall::addToWhitelist(const std::string& ip) {
    whitelist.insert(ip);
}

void Firewall::packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    Firewall* firewall = reinterpret_cast<Firewall*>(userData);
    firewall->processPacket(packet, pkthdr);
}

void Firewall::processPacket(const u_char* packet, const struct pcap_pkthdr* header) {
    struct ethhdr* ethHeader = (struct ethhdr*)packet;
    
    if (ntohs(ethHeader->h_proto) != ETH_P_IP) {
        return; // Not an IP packet
    }
    
    struct ip* ipHeader = (struct ip*)(packet + sizeof(struct ethhdr));
    struct tcphdr* tcpHeader = nullptr;
    struct udphdr* udpHeader = nullptr;
    
    if (ipHeader->ip_p == IPPROTO_TCP) {
        tcpHeader = (struct tcphdr*)(packet + sizeof(struct ethhdr) + (ipHeader->ip_hl << 2));
    } else if (ipHeader->ip_p == IPPROTO_UDP) {
        udpHeader = (struct udphdr*)(packet + sizeof(struct ethhdr) + (ipHeader->ip_hl << 2));
    }
    
    if (!isAllowed(ipHeader, tcpHeader, udpHeader)) {
        // Block the packet (in a real implementation, we would drop it)
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

bool Firewall::isAllowed(const struct ip* ipHeader, const struct tcphdr* tcpHeader, const struct udphdr* udpHeader) {
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
    for (const auto& rule : rules) {
        // Simple rule format: "allow|deny protocol src_ip dst_ip port"
        std::istringstream iss(rule);
        std::string action, protocol, ruleSrcIp, ruleDstIp;
        int port = 0;
        
        iss >> action >> protocol >> ruleSrcIp >> ruleDstIp >> port;
        
        char dstIp[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIp, INET_ADDRSTRLEN);
        
        // Check if IP matches
        if ((ruleSrcIp == "*" || ruleSrcIp == srcIp) && 
            (ruleDstIp == "*" || ruleDstIp == dstIp)) {
            
            // Check protocol
            if ((protocol == "tcp" && ipHeader->ip_p == IPPROTO_TCP) ||
                (protocol == "udp" && ipHeader->ip_p == IPPROTO_UDP) ||
                (protocol == "*")) {
                
                // Check port if specified
                if (port == 0 || 
                    (tcpHeader && ntohs(tcpHeader->th_dport) == port) ||
                    (udpHeader && ntohs(udpHeader->uh_dport) == port)) {
                    
                    return action == "allow";
                }
            }
        }
    }
    
    // Default deny
    return false;
}