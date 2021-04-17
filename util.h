#ifndef UTIL_H
#define UTIL_H

#include <QString>
#include <QStringList>

#include <arpa/inet.h>
#include <linux/tcp.h>

static QString toHex(const void *data, int len, char delimiter = ' ') {
    QString res;
    char buf[4], *p;
    const char *pdata = (const char*)data;
    const char digits[] = "0123456789abcdef";

    for (int i = 0; i < len; i++) {
        p = buf;
        if (i)
            *p++ = delimiter;
        *p++ = digits[(pdata[i] >> 4) & 0xf];
        *p++ = digits[pdata[i] & 0xf];
        *p = '\0';
        res.append(buf);
    }

    return res;
}

static QString ipv4Str(const void *addr) {
    char buf[16];
    return inet_ntop(AF_INET, addr, buf, 16);
}

static QString ipv6Str(const void *addr) {
    char buf[40];
    return inet_ntop(AF_INET6, addr, buf, 40);
}

static QString tcpFlagStr(const tcphdr* hdr) {
    QStringList list;
    if (hdr->cwr)   list.append(QString("CWR"));
    if (hdr->ece)   list.append(QString("ECE"));
    if (hdr->urg)   list.append(QString("URG"));
    if (hdr->ack)   list.append(QString("ACK"));
    if (hdr->psh)   list.append(QString("PSH"));
    if (hdr->rst)   list.append(QString("RST"));
    if (hdr->syn)   list.append(QString("SYN"));
    if (hdr->fin)   list.append(QString("FIN"));
    return list.join(",");
}

#endif // UTIL_H
