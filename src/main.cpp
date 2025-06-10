#include "include/firewall.h"
#include <csignal>
#include <cstdlib>
#include <iostream>
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
  std::cout << "  interface          Network interface to use (default: "
               "auto-detect)\n";
  std::cout << "  --list-interfaces  List available network interfaces\n";
}

int main(int argc, char *argv[]) {
  // Register signal handlers
#ifdef _WIN32
  signal(SIGINT, signalHandler);
  signal(SIGTERM, signalHandler);
#else
  struct sigaction sa;
  sa.sa_handler = signalHandler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
#endif

  std::string interface;
  std::string configPath;

  // Determine configuration path
#ifdef _WIN32
  // Use the current directory for Windows
  configPath = ".\\config\\";
#else
  // Use relative path for Linux
  configPath = "../config/";
#endif

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
        for (const auto &iface : interfaces) {
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

  std::string rulesFile = configPath + "firewall.rules";
  std::cout << "Loading rules from: " << rulesFile << std::endl;
  firewall.loadRules(rulesFile);

  // Load blacklist and whitelist
  std::string blacklistFile = configPath + "blacklist.txt";
  std::string whitelistFile = configPath + "whitelist.txt";

  // Read blacklist
  std::ifstream blacklist(blacklistFile);
  if (blacklist.is_open()) {
    std::string ip;
    while (std::getline(blacklist, ip)) {
      if (!ip.empty() && ip[0] != '#') {
        firewall.addToBlacklist(ip);
      }
    }
    blacklist.close();
  }

  // Read whitelist
  std::ifstream whitelist(whitelistFile);
  if (whitelist.is_open()) {
    std::string ip;
    while (std::getline(whitelist, ip)) {
      if (!ip.empty() && ip[0] != '#') {
        firewall.addToWhitelist(ip);
      }
    }
    whitelist.close();
  }

  firewall.start();

  return 0;
}