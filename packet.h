#ifndef PACKET_H
#define PACKET_H

#include <QString>

#include "util.h"

#include <net/ethernet.h>

class PacketInfo {
public:

    PacketInfo(uint32_t len, const void *pkt, timeval &ts)
    {
        mTs = ts;
        mLen = len;
        mPkt = new char[len];
        memcpy(mPkt, pkt, len);

        etherHeader = (ether_header*)mPkt;
        etherPayload = mPkt + sizeof(ether_header);
    }

    ~PacketInfo(void)
    {
        delete [] mPkt;
    }

    QString getTimestamp(void) const
    {
        return QString("%1.%2")
                .arg(mTs.tv_sec)
                .arg(mTs.tv_usec, 6, 10, QLatin1Char('0'));
    }

    virtual QString getSource(void) const
    {
        return toHex(etherHeader->ether_shost, 6, ':');
    }

    virtual QString getDest(void) const
    {
        return toHex(etherHeader->ether_dhost, 6, ':');
    }

    uint32_t getLen(void) const
    {
        return mLen;
    }

    virtual QString getInfo(void) const
    {
        int c = mLen > 16 ? 16 : mLen;

        return toHex(mPkt, c);
    }

private:
    timeval mTs;
    uint32_t mLen;
    char *mPkt;

    const ether_header *etherHeader;
    const char *etherPayload;
};

#endif // PACKET_H
