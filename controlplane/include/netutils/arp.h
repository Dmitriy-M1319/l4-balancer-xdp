#pragma once

#include <optional>
#include <array>
#include <string>

#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

namespace netutils
{

class Arp
{
public:
    static std::optional<std::array<uint8_t, 6>> Lookup(const std::string& ipv4, const std::string& iface);
private:
    static int get_if_index(int sock, const char *name, struct sockaddr_ll *sll);
    static int send_arp_req(int sock, struct sockaddr_ll *dst, const uint8_t *src_mac, uint32_t src_ip, uint32_t tgt_ip);
    static int recv_arp_reply(int sock, uint32_t wanted_ip, uint8_t *mac);
};

}
