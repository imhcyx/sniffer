#ifndef PACKET_H
#define PACKET_H

#include <QString>

#include "util.h"

#include <net/ethernet.h>
#include <arpa/inet.h>
#include <linux/ipv6.h>

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

struct iphdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;					// length of ip header
    unsigned int version:4;				// ip version
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;				// ip version
    unsigned int ihl:4;					// length of ip header
#endif
    uint8_t tos;								// type of service (usually set to 0)
    uint16_t tot_len;						// total length of ip data
    uint16_t id;								// ip identifier
    uint16_t frag_off;						// the offset of ip fragment
    uint8_t ttl;								// ttl of ip packet
    uint8_t protocol;						// upper layer protocol, e.g. icmp, tcp, udp
    uint16_t checksum;						// checksum of ip header
    uint32_t saddr;							// source ip address
    uint32_t daddr;							// destination ip address
};

struct icmphdr {
    uint8_t	type;				// type of icmp message
    uint8_t	code;				// icmp code
    uint16_t	checksum;
    uint16_t icmp_identifier;	// icmp identifier, used in icmp echo request
    uint16_t icmp_sequence;		// icmp sequence, used in icmp echo request
}__attribute__((packed));

#define ICMP_ECHOREQUEST		8       // echo request
#define ICMP_ECHOREPLY          0       // echo reply
#define ICMP_DEST_UNREACH       3       // destination unreachable
#define ICMP_TIME_EXCEEDED      11      // time exceeded

// codes for UNREACH
#define ICMP_NET_UNREACH        0       // network unreachable
#define ICMP_HOST_UNREACH       1       // host unreachable

// code for TIME_EXCEEDED
#define ICMP_EXC_TTL            0       // ttl count exceeded

class PacketInfo {
public:

    static PacketInfo *parse(const void *pkt, uint32_t len, const timeval &ts);

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
        etherHeader = (ether_header*)pkt;
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
        arpHeader = (ether_arp*)etherPayload;
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
            ipv6Header = (ipv6hdr*)etherPayload;
            ipPayload = etherPayload + sizeof(ipv6hdr);
        }
        else {
            isipv6 = false;
            ipv4Header = (iphdr*)etherPayload;
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
        case ICMP_ECHOREQUEST:      type = "echo request";              break;
        case ICMP_ECHOREPLY:        type = "echo reply";                break;
        case ICMP_DEST_UNREACH:
            switch (icmpHeader->code) {
            case ICMP_NET_UNREACH:  type = "net unreach";               break;
            case ICMP_HOST_UNREACH: type = "host unreach";              break;
            default:                type = "dest unreach unknown code"; break;
            }
            break;
        case ICMP_TIME_EXCEEDED:    type = "time exceeded";             break;
        default:                    type = "unknown type";              break;
        }

        return QString("ICMP %1").arg(type);
    }

protected:
    const icmphdr *icmpHeader;
    const char *icmpPayload;

    ICMPPacketInfo(PacketInfo *info)
        : IPPacketInfo(info)
    {
        icmpHeader = (icmphdr*)ipPayload;
        icmpPayload = ipPayload + sizeof(icmphdr);
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
