#include "model.h"

static QString mColumnStrings[] = {
    QString("Time"),
    QString("Source"),
    QString("Destination"),
    QString("Length"),
    QString("Data")
};

static int const mColumnCount = sizeof(mColumnStrings) / sizeof(QString);

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
            return mPktList[i]->getTimestamp();
        case 1:
            return mPktList[i]->getSource();
        case 2:
            return mPktList[i]->getDest();
        case 3:
            return mPktList[i]->getLen();
        case 4:
            return mPktList[i]->getInfo();
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

void PacketListModel::appendPacket(PacketInfo *pkt)
{
    layoutAboutToBeChanged();
    mPktList.append(pkt);
    layoutChanged();
}

void PacketListModel::clear()
{
    layoutAboutToBeChanged();
    mPktList.clear();
    layoutChanged();
}
