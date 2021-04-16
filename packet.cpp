#include "packet.h"

#include <map>

typedef PacketInfo *(*ParserFunc)(PacketInfo *);

const std::map<uint16_t, ParserFunc> etherParsers = {
    {ETHERTYPE_ARP,     &ARPPacketInfo::parse},
    {ETHERTYPE_IP,      &IPPacketInfo::parse},
    {ETHERTYPE_IPV6,    &IPv6PacketInfo::parse},
};

const std::map<uint16_t, ParserFunc> ipParsers = {
    {IPPROTO_ICMP,      &ICMPPacketInfo::parse},
    {IPPROTO_TCP,       &TCPPacketInfo::parse},
    {IPPROTO_UDP,       &UDPPacketInfo::parse},
};

PacketInfo *PacketInfo::parse(const void *pkt, uint32_t len, const timeval &ts)
{
    char *buf = new char[len];
    memcpy(buf, pkt, len);
    PacketInfo *p = new PacketInfo(buf, len, ts);

    try {
        ParserFunc parser = etherParsers.at(ntohs(p->etherHeader->ether_type));
        return parser(p);
    }
    catch (const std::out_of_range &e) {}

    return p;
}

PacketInfo *ARPPacketInfo::parse(PacketInfo *info)
{
    ARPPacketInfo *p = new ARPPacketInfo(*info);
    return p;
}

PacketInfo *IPPacketInfo::parse(PacketInfo *info)
{
    IPPacketInfo *p = new IPPacketInfo(*info);

    try {
        ParserFunc parser = ipParsers.at(p->ipHeader->protocol);
        return parser(p);
    }
    catch (const std::out_of_range &e) {}

    return p;
}

PacketInfo *ICMPPacketInfo::parse(PacketInfo *info)
{
    ICMPPacketInfo *p = new ICMPPacketInfo(*info);
    return p;
}

PacketInfo *TCPPacketInfo::parse(PacketInfo *info)
{
    TCPPacketInfo *p = new TCPPacketInfo(*info);
    return p;
}

PacketInfo *UDPPacketInfo::parse(PacketInfo *info)
{
    UDPPacketInfo *p = new UDPPacketInfo(*info);
    return p;
}

PacketInfo *IPv6PacketInfo::parse(PacketInfo *info)
{
    IPv6PacketInfo *p = new IPv6PacketInfo(*info);
    return p;
}
