#include "model.h"

static QString mColumnStrings[] = {
    QString("Time"),
    QString("Source"),
    QString("Destination"),
    QString("Length"),
    QString("Data")
};

static int const mColumnCount = sizeof(mColumnStrings) / sizeof(QString);

PacketInfo::PacketInfo(uint32_t len, const void *pkt, timeval &ts)
{
    mTs = ts;
    mLen = len;
    mPkt = new char[len];
    memcpy(mPkt, pkt, len);
}

PacketInfo::~PacketInfo(void)
{
    delete [] mPkt;
}

QString PacketInfo::getTimestamp(void) const
{
    return QString("%1.%2")
            .arg(mTs.tv_sec)
            .arg(mTs.tv_usec, 6, 10, QLatin1Char('0'));
}

QString PacketInfo::getSource(void) const
{
    return QString("");
}

QString PacketInfo::getDest(void) const
{
    return QString("");
}

uint32_t PacketInfo::getLen(void) const
{
    return mLen;
}

QString PacketInfo::getInfo(void) const
{
    QString buf;
    int c = mLen > 16 ? 16 : mLen;

    for (int i = 0; i < c; i++) {
        buf.append(QString("%1 ").arg((uint8_t)mPkt[i], 2, 16, QLatin1Char('0')));
    }

    return buf;
}

PacketListModel::PacketListModel(QObject *parent)
    : QAbstractItemModel(parent)
{
}

PacketListModel::~PacketListModel(void)
{
}

QModelIndex PacketListModel::index(int row, int column, const QModelIndex &parent) const
{
    return createIndex(row, column);
}

QModelIndex PacketListModel::parent(const QModelIndex &child) const
{
    return QModelIndex();
}

int PacketListModel::rowCount(const QModelIndex &parent) const
{
    return mPktList.size();
}

int PacketListModel::columnCount(const QModelIndex &parent) const
{
    return mColumnCount;
}

QVariant PacketListModel::data(const QModelIndex &index, int role) const
{
    int i = index.row();
    switch (role) {
    case Qt::DisplayRole:
        switch (index.column()) {
        case 0:
            return mPktList[i].getTimestamp();
        case 1:
            return mPktList[i].getSource();
        case 2:
            return mPktList[i].getDest();
        case 3:
            return mPktList[i].getLen();
        case 4:
            return mPktList[i].getInfo();
        }
    case Qt::TextAlignmentRole:
        return int(Qt::AlignLeft | Qt::AlignVCenter);
    default:
        return QVariant();
    }
}

QVariant PacketListModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role != Qt::DisplayRole)
        return QVariant();

    if (orientation == Qt::Vertical)
        return section + 1;

    if (orientation == Qt::Horizontal && section < mColumnCount)
        return mColumnStrings[section];

    return QVariant();
}

void PacketListModel::appendPacket(const PacketInfo &pkt) {
    layoutAboutToBeChanged();
    mPktList.append(pkt);
    layoutChanged();
}
