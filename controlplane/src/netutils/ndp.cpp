#include "ndp.h"
#include <arpa/inet.h>
#include <cstring>
#include <net/if.h>
#include <linux/neighbour.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>

using namespace netutils;

std::optional<std::array<uint8_t, 6>> Ndp::Lookup(const std::string& ipv6, const std::string& iface) {
    struct in6_addr addr6;
    if (inet_pton(AF_INET6, ipv6.c_str(), &addr6) != 1) {
        return std::nullopt;
    }
    
    unsigned int if_index = if_nametoindex(iface.c_str());
    if (if_index == 0) {
        return std::nullopt;
    }
    
    int sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (sock < 0) {
        return std::nullopt;
    }
    
    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return std::nullopt;
    }
    
    struct {
        struct nlmsghdr nlh;
        struct ndmsg ndm;
        char buf[256];
    } req;
    
    memset(&req, 0, sizeof(req));
    
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
    req.nlh.nlmsg_type = RTM_GETNEIGH;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = 1;
    req.nlh.nlmsg_pid = getpid();
    
    req.ndm.ndm_family = AF_INET6;
    req.ndm.ndm_ifindex = if_index;
    req.ndm.ndm_state = NUD_REACHABLE | NUD_STALE | NUD_DELAY | NUD_PROBE | NUD_PERMANENT;
    
    if (send(sock, &req, req.nlh.nlmsg_len, 0) < 0) {
        close(sock);
        return std::nullopt;
    }
    
    char buffer[16384];
    struct iovec iov = {buffer, sizeof(buffer)};
    struct sockaddr_nl peer;
    struct msghdr msg = {&peer, sizeof(peer), &iov, 1, nullptr, 0, 0};
    
    bool found = false;
    std::array<uint8_t, 6> mac_addr{};
    
    while (!found) {
        ssize_t len = recvmsg(sock, &msg, 0);
        if (len < 0) {
            break;
        }
        
        struct nlmsghdr* nlh = (struct nlmsghdr*)buffer;
        
        while (NLMSG_OK(nlh, static_cast<size_t>(len))) {
            if (nlh->nlmsg_type == NLMSG_DONE) {
                break;
            }
            
            if (nlh->nlmsg_type == NLMSG_ERROR) {
                close(sock);
                return std::nullopt;
            }
            
            if (nlh->nlmsg_type == RTM_NEWNEIGH) {
                struct ndmsg* ndm = (struct ndmsg*)NLMSG_DATA(nlh);
                struct rtattr* rta = (struct rtattr*)RTM_RTA(ndm);
                int rta_len = RTM_PAYLOAD(nlh);
                
                if (ndm->ndm_family == AF_INET6 && ndm->ndm_ifindex == if_index) {
                    struct in6_addr dst_addr;
                    bool has_addr = false;
                    bool has_lladdr = false;
                    unsigned char lladdr[6];
                    
                    while (RTA_OK(rta, rta_len)) {
                        if (rta->rta_type == NDA_DST && rta->rta_len == RTA_LENGTH(sizeof(struct in6_addr))) {
                            memcpy(&dst_addr, RTA_DATA(rta), sizeof(struct in6_addr));
                            has_addr = true;
                        } else if (rta->rta_type == NDA_LLADDR && rta->rta_len == RTA_LENGTH(6)) {
                            memcpy(lladdr, RTA_DATA(rta), 6);
                            has_lladdr = true;
                        }
                        rta = RTA_NEXT(rta, rta_len);
                    }
                    
                    if (has_addr && has_lladdr && memcmp(&dst_addr, &addr6, sizeof(addr6)) == 0) {
                        memcpy(mac_addr.data(), lladdr, 6);
                        found = true;
                        break;
                    }
                }
            }
            
            nlh = NLMSG_NEXT(nlh, len);
        }
    }
    
    close(sock);
    
    if (found) {
        return mac_addr;
    }
    
    return std::nullopt;
}