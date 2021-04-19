#include "packet.h"

#include <map>

typedef PacketInfo *(*ParserFunc)(PacketInfo *);

const std::map<uint16_t, ParserFunc> etherParsers = {
    {ETHERTYPE_ARP,     &ARPPacketInfo::parse},
    {ETHERTYPE_IP,      &IPPacketInfo::parse},
    {ETHERTYPE_IPV6,    &IPPacketInfo::parse},
};

const std::map<uint16_t, ParserFunc> ipParsers = {
    {IPPROTO_ICMP,      &ICMPPacketInfo::parse},
    {IPPROTO_ICMPV6,    &ICMPv6PacketInfo::parse},
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
    ARPPacketInfo *p = new ARPPacketInfo(info);
    return p;
}

PacketInfo *IPPacketInfo::parse(PacketInfo *info)
{
    IPPacketInfo *p = new IPPacketInfo(info);

    try {
        uint8_t protocol = p->isipv6 ?
                    p->ipv6Header->nexthdr :
                    p->ipv4Header->protocol;
        ParserFunc parser = ipParsers.at(protocol);
        return parser(p);
    }
    catch (const std::out_of_range &e) {}

    return p;
}

PacketInfo *ICMPPacketInfo::parse(PacketInfo *info)
{
    ICMPPacketInfo *p = new ICMPPacketInfo(info);
    return p;
}

PacketInfo *ICMPv6PacketInfo::parse(PacketInfo *info)
{
    ICMPv6PacketInfo *p = new ICMPv6PacketInfo(info);
    return p;
}

PacketInfo *TCPPacketInfo::parse(PacketInfo *info)
{
    TCPPacketInfo *p = new TCPPacketInfo(info);

    if (HTTPRequest *r = HTTPRequest::parse(p->tcpPayload)) {
        return HTTPPacketInfo::req(p, r);
    }

    if (HTTPResponse *r = HTTPResponse::parse(p->tcpPayload)) {
        return HTTPPacketInfo::resp(p, r);
    }

    return p;
}

PacketInfo *HTTPPacketInfo::req(PacketInfo *info, HTTPRequest *r)
{
    HTTPPacketInfo *http = new HTTPPacketInfo(info, r);
    http->ishttprequest = true;

    return http;
}

PacketInfo *HTTPPacketInfo::resp(PacketInfo *info, HTTPResponse *r)
{
    HTTPPacketInfo *http = new HTTPPacketInfo(info, r);
    http->ishttprequest = false;

    return http;
}

PacketInfo *UDPPacketInfo::parse(PacketInfo *info)
{
    UDPPacketInfo *p = new UDPPacketInfo(info);
    return p;
}
