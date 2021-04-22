#include "model.h"

static QString mColumnStrings[] = {
    QString("Time"),
    QString("Source"),
    QString("Destination"),
    QString("Length"),
    QString("Protocol"),
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
    return mFilteredList.size();
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
            return mFilteredList[i]->getTimestamp();
        case 1:
            return mFilteredList[i]->getSource();
        case 2:
            return mFilteredList[i]->getDest();
        case 3:
            return mFilteredList[i]->getLen();
        case 4:
            return mFilteredList[i]->getProto();
        case 5:
            return mFilteredList[i]->getInfo();
        }
        break;
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

void PacketListModel::applyFilter(FilterFunc filter)
{
    layoutAboutToBeChanged();
    mFilter = filter;
    mFilteredList.clear();
    for (PacketInfo *p : mPktList)
        if (!mFilter || mFilter(p))
            mFilteredList.append(p);
    layoutChanged();
}

void PacketListModel::appendPacket(PacketInfo *pkt)
{
    layoutAboutToBeChanged();
    mPktList.append(pkt);
    if (!mFilter || mFilter(pkt))
        mFilteredList.append(pkt);
    layoutChanged();
}

PacketInfo &PacketListModel::getPacket(const QModelIndex &index)
{
    return *mFilteredList[index.row()];
}

void PacketListModel::clear()
{
    layoutAboutToBeChanged();
    mPktList.clear();
    mFilteredList.clear();
    layoutChanged();
}
