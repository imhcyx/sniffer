#include "packet.h"

#include <map>

typedef PacketInfo *(*ParserFunc)(PacketInfo *);

const std::map<uint16_t, ParserFunc> etherParsers = {
    {ETHERTYPE_ARP,     &ARPPacketInfo::parse},
    {ETHERTYPE_IP,      &IPv4PacketInfo::parse},
    {ETHERTYPE_IPV6,    &IPv6PacketInfo::parse},
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

PacketInfo *IPv4PacketInfo::parse(PacketInfo *info)
{
    IPv4PacketInfo *p = new IPv4PacketInfo(*info);
    return p;
}

PacketInfo *IPv6PacketInfo::parse(PacketInfo *info)
{
    IPv6PacketInfo *p = new IPv6PacketInfo(*info);
    return p;
}
