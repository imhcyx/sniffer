#ifndef MODEL_H
#define MODEL_H

#include <QAbstractItemModel>
#include <QList>

#include "packet.h"

class PacketListModel : public QAbstractItemModel
{
public:
    explicit PacketListModel(QObject *parent = 0);
    ~PacketListModel(void);

    virtual QModelIndex index(int row, int column, const QModelIndex &parent = QModelIndex()) const override;
    virtual QModelIndex parent(const QModelIndex &child) const override;
    virtual int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    virtual int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    virtual QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    virtual QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const;

    void appendPacket(const PacketInfo &pkt);
    void clear();

private:
    QList<PacketInfo> mPktList;
};

#endif // MODEL_H
