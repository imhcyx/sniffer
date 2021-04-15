#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QMessageBox>
#include <QTime>
#include <QThread>

#include "model.h"
#include "capture.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

signals:
    void startCapture(QString ifname);
    void stopCapture();

private slots:
    void on_startButton_clicked();
    void on_stopButton_clicked();
    void packetCaptured(PacketInfo *info);
    void errorMsg(const char *msg);
    void stateChanged(bool state);

private:
    Ui::MainWindow *ui;
    PacketListModel *pktlist;
    CaptureThread *cap;
    QThread *thread;
    bool running;

    void captureStartStop(bool start);
};
#endif // MAINWINDOW_H
