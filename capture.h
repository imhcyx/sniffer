#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>

#include <QStringList>

#include "model.h"

QStringList getCaptureIfs(QWidget *parent = nullptr);

class CaptureThread : public QObject
{
    Q_OBJECT

public:
    void stop();

public slots:
    void run(QString ifname);

signals:
    void packetCaptured(PacketInfo *info);
    void errorMsg(const char* msg);
    void stateChanged(bool state);

private:
    bool mRunning;

    void changeState(bool state);
};

#endif // CAPTURE_H
