#ifndef PACKET_H
#define PACKET_H

#include <QString>

#include "util.h"

#include <net/ethernet.h>
#include <arpa/inet.h>

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

class PacketInfo {
public:

    static PacketInfo *parse(const void *pkt, uint32_t len, const timeval &ts);

    ~PacketInfo(void)
    {
        // TODO: free resource somewhere
        //delete [] packet;
    }

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
    const char *packet;
    uint32_t length;
    timeval timestamp;

    const ether_header *etherHeader;
    const char *etherPayload;

    PacketInfo(const char *pkt, uint32_t len, const timeval &ts)
        : packet(pkt), length(len), timestamp(ts)
    {
        etherHeader = (ether_header*)packet;
        etherPayload = packet + sizeof(ether_header);
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

    ARPPacketInfo(PacketInfo &info)
        : PacketInfo(info)
    {
        arpHeader = (ether_arp*)etherPayload;
        arpPayload = etherPayload + sizeof(ether_arp);
    }
};

class IPv4PacketInfo : public PacketInfo
{
public:

    static PacketInfo *parse(PacketInfo *info);

    virtual QString getSource(void) const
    {
        return ipv4Str(&ipv4Header->saddr);
    }

    virtual QString getDest(void) const
    {
        return ipv4Str(&ipv4Header->daddr);
    }

    virtual QString getInfo(void) const
    {
        return QString("IPv4 packet");
    }

protected:
    const iphdr *ipv4Header;
    const char *ipv4Payload;

    IPv4PacketInfo(PacketInfo &info)
        : PacketInfo(info)
    {
        ipv4Header = (iphdr*)etherPayload;
        ipv4Payload = etherPayload + (ipv4Header->ihl << 2);
    }
};

class IPv6PacketInfo : public PacketInfo
{
public:

    static PacketInfo *parse(PacketInfo *info);

    virtual QString getInfo(void) const
    {
        return QString("IPv6 packet");
    }

protected:
    IPv6PacketInfo(PacketInfo &info)
        : PacketInfo(info) {}
};

#endif // PACKET_H
