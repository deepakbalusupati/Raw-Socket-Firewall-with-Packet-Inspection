#ifndef FIREWALL_H
#define FIREWALL_H

#include "platform.h"

class Firewall {
public:
  Firewall();
  ~Firewall();

  bool init(const std::string &interface = "");
  void start();
  void stop();
  void loadRules(const std::string &ruleFile);
  void addToBlacklist(const std::string &ip);
  void addToWhitelist(const std::string &ip);
  static std::vector<std::string> getAvailableInterfaces();

private:
  pcap_t *pcapHandle;
  std::string interface;
  std::vector<std::string> rules;
  std::unordered_set<std::string> blacklist;
  std::unordered_set<std::string> whitelist;
  bool running;

  void processPacket(const u_char *packet, const struct pcap_pkthdr *header);
  bool isAllowed(const struct ip *ipHeader, const struct tcphdr *tcpHeader,
                 const struct udphdr *udpHeader);
  static void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr,
                            const u_char *packet);
};

#endif // FIREWALL_H