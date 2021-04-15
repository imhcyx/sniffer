#include "capture.h"

#include <QMessageBox>

QStringList getCaptureIfs(QWidget *parent)
{
    pcap_if_t *list, *p;
    int ret;
    char errbuf[PCAP_ERRBUF_SIZE];
    QStringList nameList;

    ret = pcap_findalldevs(&list, errbuf);
    if (ret) {
        QMessageBox msg(parent);
        msg.setWindowTitle("Error");
        msg.setText(QString("pcap_findalldevs: %1").arg(errbuf));
        msg.setIcon(QMessageBox::Critical);
        msg.exec();
        return nameList;
    }

    for (p = list; p; p = p->next) {
        nameList.append(p->name);
    }

    pcap_freealldevs(list);

    return nameList;
}

void CaptureThread::changeState(bool state) {
    mRunning = state;
    emit stateChanged(state);
}

void CaptureThread::stop() {
    qDebug("CaptureThread::stop");
    this->changeState(false);
}

void CaptureThread::run(QString ifname)
{
    qDebug("CaptureThread::run");

    int ret;
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    pcap_pkthdr *phdr;
    pcap_t *descr = pcap_open_live(qPrintable(ifname), BUFSIZ, 0, -1, errbuf);

    if (!descr) {
        emit errorMsg(errbuf);
        return;
    }

    qDebug("entering capture loop");

    this->changeState(true);
    while (mRunning) {
        ret = pcap_next_ex(descr, &phdr, &packet);
        if (ret == 1) {
            PacketInfo *info = new PacketInfo(phdr->caplen, packet, phdr->ts);
            emit packetCaptured(info);
        }
        else if (ret) {
            emit errorMsg(pcap_geterr(descr));
            this->changeState(false);
        }
    }

    qDebug("capture thread exiting");

    pcap_close(descr);
}
