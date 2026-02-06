#include "arp.h"
#include <cstring>
#include <unistd.h>
#include <iostream>
#include <cstdio>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

namespace
{
constexpr int ARP_WAIT_MS = 5000;
constexpr int BUF_SIZE    = 2048;

void logErr(const char *ctx)
{
    std::cerr << "[ARP] " << ctx << ": " << std::strerror(errno) << '\n';
}
}

using namespace netutils;

int Arp::get_if_index(int sock, const char *name, struct sockaddr_ll *sll)
{
    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0)
    {
        logErr("ioctl SIOCGIFINDEX");
        return -1;
    }

    std::memset(sll, 0, sizeof(*sll));
    sll->sll_family   = AF_PACKET;
    sll->sll_ifindex  = ifr.ifr_ifindex;
    sll->sll_protocol = htons(ETH_P_ARP);
    return 0;
}

int Arp::send_arp_req(int sock, struct sockaddr_ll *dst,
                      const uint8_t *src_mac, uint32_t src_ip, uint32_t tgt_ip)
{
    uint8_t buf[BUF_SIZE] = {0};

    auto *eth = reinterpret_cast<struct ethhdr *>(buf);
    auto *arp = reinterpret_cast<struct arphdr *>(buf + sizeof(struct ethhdr));

    std::memset(eth->h_dest, 0xff, ETH_ALEN);
    std::memcpy(eth->h_source, src_mac, ETH_ALEN);
    eth->h_proto = htons(ETH_P_ARP);

    arp->ar_hrd = htons(ARPHRD_ETHER);
    arp->ar_pro = htons(ETH_P_IP);
    arp->ar_hln = ETH_ALEN;
    arp->ar_pln = 4;
    arp->ar_op  = htons(ARPOP_REQUEST);

    uint8_t *arp_sha = reinterpret_cast<uint8_t *>(arp + 1);
    uint8_t *arp_spa = arp_sha + ETH_ALEN;
    uint8_t *arp_tha = arp_spa + 4;
    uint8_t *arp_tpa = arp_tha + ETH_ALEN;

    std::memcpy(arp_sha, src_mac, ETH_ALEN);
    std::memcpy(arp_spa, &src_ip, 4);
    std::memset(arp_tha, 0, ETH_ALEN);
    std::memcpy(arp_tpa, &tgt_ip, 4);

    int len = sizeof(struct ethhdr) + sizeof(struct arphdr) + 2 * ETH_ALEN + 2 * 4;
    if (sendto(sock, buf, len, 0,
               reinterpret_cast<struct sockaddr *>(dst), sizeof(*dst)) != len)
    {
        logErr("sendto");
        return -1;
    }
    return 0;
}

int Arp::recv_arp_reply(int sock, uint32_t wanted_ip, uint8_t *mac)
{
    uint8_t buf[BUF_SIZE];
    struct sockaddr_ll from{};
    socklen_t fromlen = sizeof(from);

    struct timeval tv{ARP_WAIT_MS / 1000, (ARP_WAIT_MS % 1000) * 1000};
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        logErr("setsockopt SO_RCVTIMEO");
        return -1;
    }

    while (true)
    {
        ssize_t n = recvfrom(sock, buf, sizeof(buf), 0,
                             reinterpret_cast<struct sockaddr *>(&from), &fromlen);
        if (n < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                std::cerr << "[ARP] recvfrom: timeout (" << ARP_WAIT_MS << " ms)\n";
            else
                logErr("recvfrom");
            return -1;
        }

        if (n < static_cast<ssize_t>(sizeof(struct ethhdr) + sizeof(struct arphdr)))
            continue;

        auto *eth = reinterpret_cast<struct ethhdr *>(buf);
        auto *arp = reinterpret_cast<struct arphdr *>(buf + sizeof(struct ethhdr));

        if (ntohs(eth->h_proto) != ETH_P_ARP || ntohs(arp->ar_op) != ARPOP_REPLY)
            continue;

        uint8_t *arp_spa = reinterpret_cast<uint8_t *>(arp + 1) + ETH_ALEN;
        uint32_t spa;
        std::memcpy(&spa, arp_spa, 4);

        if (spa == wanted_ip)
        {
            uint8_t *arp_sha = reinterpret_cast<uint8_t *>(arp + 1);
            std::memcpy(mac, arp_sha, ETH_ALEN);
            return 0;
        }
    }
}


std::optional<std::array<uint8_t, 6>> Arp::Lookup(const std::string& ipv4, const std::string& iface)
{
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0)
    {
        logErr("socket(AF_PACKET)");
        return std::nullopt;
    }

    sockaddr_ll sll{};
    if (get_if_index(sock, iface.c_str(), &sll) < 0)
    {
        close(sock);
        return std::nullopt;
    }

    ifreq ifr{};
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);

    uint8_t src_mac[ETH_ALEN]{};
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
    {
        logErr("ioctl SIOCGIFHWADDR");
        close(sock);
        return std::nullopt;
    }
    std::memcpy(src_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0)
    {
        //logErr("ioctl SIOCGIFADDR");
        close(sock);
        return std::nullopt;
    }
    uint32_t src_ip = reinterpret_cast<sockaddr_in*>(&ifr.ifr_addr)->sin_addr.s_addr;

    uint32_t tgt_ip = inet_addr(ipv4.c_str());
    if (tgt_ip == INADDR_NONE)
    {
        std::cerr << "[ARP] invalid IPv4: " << ipv4 << '\n';
        close(sock);
        return std::nullopt;
    }

    if (bind(sock, reinterpret_cast<struct sockaddr *>(&sll), sizeof(sll)) < 0)
    {
        logErr("bind");
        close(sock);
        return std::nullopt;
    }

    if (send_arp_req(sock, &sll, src_mac, src_ip, tgt_ip) < 0)
    {
        close(sock);
        return std::nullopt;
    }

    uint8_t mac[6]{};
    if (recv_arp_reply(sock, tgt_ip, mac) < 0)
    {
        close(sock);
        return std::nullopt;
    }

    close(sock);
    std::array<uint8_t, 6> out;
    std::copy(std::begin(mac), std::end(mac), out.begin());
    return out;
}
