#include "../include/firewall.h"
#include <iostream>
#include <string>

bool inspectHTTP(const u_char* payload, int size) {
    const char* data = reinterpret_cast<const char*>(payload);
    std::string packet(data, size);
    
    if (packet.find("' OR '1'='1") != std::string::npos ||
        packet.find("UNION SELECT") != std::string::npos) {
        return false;
    }
    
    if (packet.find("<script>") != std::string::npos ||
        packet.find("javascript:") != std::string::npos) {
        return false;
    }
    
    return true;
}