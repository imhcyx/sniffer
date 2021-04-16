#ifndef UTIL_H
#define UTIL_H

#include <QString>

#include <arpa/inet.h>

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

#endif // UTIL_H
