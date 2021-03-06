#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , pktlist(new PacketListModel(parent))
    , detaillist(new QStringListModel(parent))
{
    ui->setupUi(this);
    hexView = new QHexView(ui->bottomSpillter);

    ui->pktView->setModel(pktlist);
    ui->pktView->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->pktView->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    ui->pktView->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    ui->pktView->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    ui->pktView->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    ui->pktView->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);

    ui->detailView->setModel(detaillist);

    ui->filterCombo->addItems(FilterNameList);

    QStringList ifList = getCaptureIfs(this);
    ui->ifaceCombo->addItems(ifList);

    cap = new CaptureThread();
    thread = new QThread(this);
    cap->moveToThread(thread);
    connect(this, SIGNAL(startCapture(QString)), cap, SLOT(run(QString)));
    connect(cap, SIGNAL(packetCaptured(PacketInfo*)), this, SLOT(packetCaptured(PacketInfo*)));
    connect(cap, SIGNAL(errorMsg(const char*)), this, SLOT(errorMsg(const char*)));
    connect(cap, SIGNAL(stateChanged(bool)), this, SLOT(stateChanged(bool)));
    thread->start();

    running = false;
}

MainWindow::~MainWindow()
{
    captureStartStop(false);
    thread->exit();
    thread->wait();
    delete cap;
    delete thread;
    delete detaillist;
    delete pktlist;
    delete hexView;
    delete ui;
}

void MainWindow::captureStartStop(bool start) {
    if (start == running)
        return;

    if (start) {
        qDebug("start capture");
        emit startCapture(ui->ifaceCombo->currentText());
    }
    else {
        qDebug("stop capture");
        cap->stop();
    }
}

void MainWindow::on_startButton_clicked()
{
    captureStartStop(true);
}

void MainWindow::on_stopButton_clicked()
{
    captureStartStop(false);
}

void MainWindow::on_clearButton_clicked()
{
    pktlist->clear();
}

void MainWindow::packetCaptured(PacketInfo *info)
{
    pktlist->appendPacket(info);
    if (ui->checkScroll->isChecked())
        ui->pktView->scrollToBottom();
}

void MainWindow::errorMsg(const char *msg)
{
    QMessageBox msgbox(this);
    msgbox.setWindowTitle("Error");
    msgbox.setText(QString("Capture error: %1").arg(msg));
    msgbox.setIcon(QMessageBox::Critical);
    msgbox.exec();
}

void MainWindow::stateChanged(bool state)
{
    ui->startButton->setEnabled(!state);
    ui->stopButton->setEnabled(state);

    running = state;
}

void MainWindow::on_pktView_clicked(const QModelIndex &index)
{
    PacketInfo &info = pktlist->getPacket(index);
    QStringList detail = info.walkDetail();
    detaillist->setStringList(detail);
    QByteArray arr(info.getData());
    hexView->setData(new QHexView::DataStorageArray(arr));
    hexView->viewport()->update();
}

void MainWindow::on_filterCombo_currentTextChanged(const QString &arg1)
{
    pktlist->applyFilter(FilterFuncList[ui->filterCombo->currentIndex()]);
}
