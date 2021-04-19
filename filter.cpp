#include "filter.h"

static bool arpFilter(PacketInfo *info) {
    return dynamic_cast<ARPPacketInfo*>(info);
}

static bool ipv4Filter(PacketInfo *info) {
    IPPacketInfo *p = dynamic_cast<IPPacketInfo*>(info);
    if (p && !p->isIPv6())
        return true;
    return false;
}

static bool ipv6Filter(PacketInfo *info) {
    IPPacketInfo *p = dynamic_cast<IPPacketInfo*>(info);
    if (p && p->isIPv6())
        return true;
    return false;
}

static bool icmpFilter(PacketInfo *info) {
    return dynamic_cast<ICMPPacketInfo*>(info);
}

static bool icmpv6Filter(PacketInfo *info) {
    return dynamic_cast<ICMPv6PacketInfo*>(info);
}

static bool tcpFilter(PacketInfo *info) {
    return dynamic_cast<TCPPacketInfo*>(info);
}

static bool udpFilter(PacketInfo *info) {
    return dynamic_cast<UDPPacketInfo*>(info);
}

static bool httpFilter(PacketInfo *info) {
    return dynamic_cast<HTTPPacketInfo*>(info);
}

const QStringList FilterNameList = {
    "all",
    "arp",
    "ipv4",
    "ipv6",
    "icmp",
    "icmpv6",
    "tcp",
    "udp",
    "http",
};

const PacketListModel::FilterFunc FilterFuncList[] = {
    nullptr,
    &arpFilter,
    &ipv4Filter,
    &ipv6Filter,
    &icmpFilter,
    &icmpv6Filter,
    &tcpFilter,
    &udpFilter,
    &httpFilter,
};
