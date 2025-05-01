#include "include/firewall.h"
#include <iostream>
#include <csignal>
#include <thread>

Firewall firewall;

void signalHandler(int signum) {
    std::cout << "Interrupt signal (" << signum << ") received.\n";
    firewall.stop();
    exit(signum);
}

void showHelp() {
    std::cout << "Usage:\n";
    std::cout << "  firewall [interface]\n";
    std::cout << "  firewall --list-interfaces\n";
    std::cout << "\nOptions:\n";
    std::cout << "  interface          Network interface to use (default: auto-detect)\n";
    std::cout << "  --list-interfaces  List available network interfaces\n";
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    std::string interface;
    if (argc > 1) {
        if (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h") {
            showHelp();
            return 0;
        } else if (std::string(argv[1]) == "--list-interfaces") {
            auto interfaces = Firewall::getAvailableInterfaces();
            if (interfaces.empty()) {
                std::cout << "No network interfaces found!" << std::endl;
            } else {
                std::cout << "Available network interfaces:" << std::endl;
                for (const auto& iface : interfaces) {
                    std::cout << "  - " << iface << std::endl;
                }
            }
            return 0;
        } else {
            interface = argv[1];
        }
    }
    
    if (!firewall.init(interface)) {
        return 1;
    }
    
    firewall.loadRules("../config/firewall.rules");
    firewall.addToBlacklist("192.168.1.100");
    firewall.addToBlacklist("10.0.0.5");
    
    firewall.start();
    
    return 0;
}