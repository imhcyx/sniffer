#ifndef UTIL_H
#define UTIL_H

#include <QString>

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
    const uint8_t *p = (const uint8_t*)addr;
    return QString("%1.%2.%3.%4").arg(p[0]).arg(p[1]).arg(p[2]).arg(p[3]);
}

#endif // UTIL_H
