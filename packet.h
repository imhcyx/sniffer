#ifndef PACKET_H
#define PACKET_H

#include <QString>

#include "util.h"

#include <net/ethernet.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include <memory>

#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2

struct ether_arp {
    uint16_t    arp_hrd;		// format of hardware address, should be 0x01
    uint16_t    arp_pro;		// format of protocol address, should be 0x0800
    uint8_t     arp_hln;		// length of hardware address, should be 6
    uint8_t     arp_pln;		// length of protocol address, should be 4
    uint16_t    arp_op;			// ARP opcode (command)
    uint8_t     arp_sha[ETH_ALEN];	// sender hardware address
    uint32_t	arp_spa;		// sender protocol address
    uint8_t     arp_tha[ETH_ALEN];	// target hardware address
    uint32_t	arp_tpa;		// target protocol address
} __attribute__ ((packed));

class PacketInfo {
public:

    static PacketInfo *parse(const void *pkt, uint32_t len, const timeval &ts);

    virtual ~PacketInfo() {}

    QString getTimestamp(void) const
    {
        return QString("%1.%2")
                .arg(timestamp.tv_sec)
                .arg(timestamp.tv_usec, 6, 10, QLatin1Char('0'));
    }

    uint32_t getLen(void) const
    {
        return length;
    }

    virtual QString getSource(void) const
    {
        return toHex(etherHeader->ether_shost, 6, ':');
    }

    virtual QString getDest(void) const
    {
        return toHex(etherHeader->ether_dhost, 6, ':');
    }

    virtual QString getInfo(void) const
    {
        return QString("Ethernet packet of type 0x%1").arg(ntohs(etherHeader->ether_type), 0, 16);
    }

protected:
    std::unique_ptr<const char> packet;
    uint32_t length;
    timeval timestamp;

    const ether_header *etherHeader;
    const char *etherPayload;

    PacketInfo(const char *pkt, uint32_t len, const timeval &ts)
        : packet(pkt), length(len), timestamp(ts)
    {
        etherHeader = (const ether_header*)pkt;
        etherPayload = pkt + sizeof(ether_header);
    }

    PacketInfo(PacketInfo *info)
        : PacketInfo(info->packet.release(), info->length, info->timestamp)
    {
        delete info;
    }
};

class ARPPacketInfo : public PacketInfo
{
public:

    static PacketInfo *parse(PacketInfo *info);

    virtual QString getInfo(void) const
    {
        const char *opstr;
        switch (ntohs(arpHeader->arp_op)) {
        case ARPOP_REQUEST: opstr = "request";  break;
        case ARPOP_REPLY:   opstr = "reply";    break;
        default:            opstr = "unknown";  break;
        }

        return QString("ARP %1 from %2 to %3").arg(
                    QString(opstr),
                    ipv4Str(&arpHeader->arp_spa),
                    ipv4Str(&arpHeader->arp_tpa));
    }

protected:
    const ether_arp *arpHeader;
    const char *arpPayload;

    ARPPacketInfo(PacketInfo *info)
        : PacketInfo(info)
    {
        arpHeader = (const ether_arp*)etherPayload;
        arpPayload = etherPayload + sizeof(ether_arp);
    }
};

class IPPacketInfo : public PacketInfo
{
public:

    static PacketInfo *parse(PacketInfo *info);

    virtual QString getSource(void) const
    {
        if (isipv6)
            return ipv6Str(&ipv6Header->saddr);
        else
            return ipv4Str(&ipv4Header->saddr);
    }

    virtual QString getDest(void) const
    {
        if (isipv6)
            return ipv6Str(&ipv6Header->daddr);
        else
            return ipv4Str(&ipv4Header->daddr);
    }

    virtual QString getInfo(void) const
    {
        if (isipv6)
            return QString("IPv6 packet of type 0x%1").arg(ipv6Header->nexthdr, 0, 16);
        else
            return QString("IPv4 packet of type 0x%1").arg(ipv4Header->protocol, 0, 16);
    }

protected:
    bool isipv6;
    union {
        const iphdr *ipv4Header;
        const ipv6hdr *ipv6Header;
    };
    const char *ipPayload;

    IPPacketInfo(PacketInfo *info)
        : PacketInfo(info)
    {
        if (ntohs(etherHeader->ether_type) == ETHERTYPE_IPV6) {
            isipv6 = true;
            ipv6Header = (const ipv6hdr*)etherPayload;
            ipPayload = etherPayload + sizeof(ipv6hdr);
        }
        else {
            isipv6 = false;
            ipv4Header = (const iphdr*)etherPayload;
            ipPayload = etherPayload + (ipv4Header->ihl << 2);
        }
    }
};

class ICMPPacketInfo : public IPPacketInfo
{
public:

    static PacketInfo *parse(PacketInfo *info);

    virtual QString getInfo(void) const
    {
        const char *type;
        switch(icmpHeader->type) {
        case ICMP_ECHO:             type = "echo request";      break;
        case ICMP_ECHOREPLY:        type = "echo reply";        break;
        case ICMP_DEST_UNREACH:
            switch (icmpHeader->code) {
            case ICMP_NET_UNREACH:  type = "net unreach";       break;
            case ICMP_HOST_UNREACH: type = "host unreach";      break;
            default:
                return QString("ICMP dest unreach of code 0x%1")
                        .arg(icmpHeader->code, 0, 16);
            }
            break;
        case ICMP_TIME_EXCEEDED:    type = "time exceeded";     break;
        default:
            return QString("ICMP packet of type 0x%1")
                    .arg(icmpHeader->type, 0, 16);
        }

        return QString("ICMP %1").arg(type);
    }

protected:
    const icmphdr *icmpHeader;
    const char *icmpPayload;

    ICMPPacketInfo(PacketInfo *info)
        : IPPacketInfo(info)
    {
        icmpHeader = (const icmphdr*)ipPayload;
        icmpPayload = ipPayload + sizeof(icmphdr);
    }
};

class ICMPv6PacketInfo : public IPPacketInfo
{
public:

    static PacketInfo *parse(PacketInfo *info);

    virtual QString getInfo(void) const
    {
        const char *type;
        switch (icmpv6Header->icmp6_type) {
        case ICMPV6_DEST_UNREACH:
            switch (icmpv6Header->icmp6_code) {
            case ICMPV6_NOROUTE:        type = "no route";      break;
            case ICMPV6_ADDR_UNREACH:   type = "addr unreach";  break;
            case ICMPV6_PORT_UNREACH:   type = "port unreach";  break;
            default:
                return QString("ICMPv6 dest unreach of code 0x%1")
                        .arg(icmpv6Header->icmp6_code, 0, 16);
            }
        case ICMPV6_TIME_EXCEED:        type = "time exceeded"; break;
        case ICMPV6_ECHO_REQUEST:       type = "echo request";  break;
        case ICMPV6_ECHO_REPLY:         type = "echo reply";    break;
        default:
            return QString("ICMPv6 packet of type 0x%1")
                    .arg(icmpv6Header->icmp6_type, 0, 16);
        }

        return QString("ICMPv6 %1").arg(type);
    }

protected:
    const icmp6hdr *icmpv6Header;
    const char *icmpv6Payload;

    ICMPv6PacketInfo(PacketInfo *info)
        : IPPacketInfo(info)
    {
        icmpv6Header = (const icmp6hdr*)ipPayload;
        icmpv6Payload = ipPayload + sizeof(icmp6hdr);
    }
};

class TCPPacketInfo : public IPPacketInfo
{
public:
    static PacketInfo *parse(PacketInfo *info);

    virtual QString getInfo(void) const
    {
        return QString("TCP packet");
    }

protected:
    TCPPacketInfo(PacketInfo *info)
        : IPPacketInfo(info) {}
};

class UDPPacketInfo : public IPPacketInfo
{
public:
    static PacketInfo *parse(PacketInfo *info);

    virtual QString getInfo(void) const
    {
        return QString("UDP packet");
    }

protected:
    UDPPacketInfo(PacketInfo *info)
        : IPPacketInfo(info) {}
};

#endif // PACKET_H
