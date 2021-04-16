#ifndef PACKET_H
#define PACKET_H

#include <QString>

#include "util.h"

#include <net/ethernet.h>
#include <arpa/inet.h>

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

private:
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
        return QString("ARP packet");
    }

private:
    ARPPacketInfo(PacketInfo &info)
        : PacketInfo(info) {}
};

class IPv4PacketInfo : public PacketInfo
{
public:

    static PacketInfo *parse(PacketInfo *info);

    virtual QString getInfo(void) const
    {
        return QString("IPv4 packet");
    }

private:
    IPv4PacketInfo(PacketInfo &info)
        : PacketInfo(info) {}
};

class IPv6PacketInfo : public PacketInfo
{
public:

    static PacketInfo *parse(PacketInfo *info);

    virtual QString getInfo(void) const
    {
        return QString("IPv6 packet");
    }

private:
    IPv6PacketInfo(PacketInfo &info)
        : PacketInfo(info) {}
};

#endif // PACKET_H
