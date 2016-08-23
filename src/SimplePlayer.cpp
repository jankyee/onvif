/*
* VLC-Qt Simple Player
* Copyright (C) 2015 Tadej Novak <tadej@tano.si>
*/

#include <QFileDialog>
#include <QInputDialog>

#include <VLCQtCore/Common.h>
#include <VLCQtCore/Instance.h>
#include <VLCQtCore/Media.h>
#include <VLCQtCore/MediaPlayer.h>

#include "SimplePlayer.h"
#include "ui_SimplePlayer.h"
#include "cap.h"

extern char *rtsp_addr;

SimplePlayer::SimplePlayer(QWidget *parent)
    : QMainWindow(parent),
      ui(new Ui::SimplePlayer),
      _media(0)
{
    ui->setupUi(this);

    _instance = new VlcInstance(VlcCommon::args(), this);
    _player = new VlcMediaPlayer(_instance);
    _player->setVideoWidget(ui->video);

    ui->video->setMediaPlayer(_player);
    ui->volume->setMediaPlayer(_player);
    ui->volume->setVolume(50);
    ui->seek->setMediaPlayer(_player);

    connect(ui->actionOpenLocal, &QAction::triggered, this, &SimplePlayer::openLocal);
    connect(ui->actionOpenUrl, &QAction::triggered, this, &SimplePlayer::openUrl);
    connect(ui->actionPause, &QAction::toggled, _player, &VlcMediaPlayer::togglePause);
    connect(ui->actionStop, &QAction::triggered, _player, &VlcMediaPlayer::stop);
    connect(ui->openLocal, &QPushButton::clicked, this, &SimplePlayer::openLocal);
    connect(ui->openUrl, &QPushButton::clicked, this, &SimplePlayer::openUrl);
    connect(ui->pause, &QPushButton::toggled, ui->actionPause, &QAction::toggle);
    connect(ui->stop, &QPushButton::clicked, _player, &VlcMediaPlayer::stop);
}

SimplePlayer::~SimplePlayer()
{
    delete _player;
    delete _media;
    delete _instance;
    delete ui;
}

void SimplePlayer::openLocal()
{
    QString file =
            QFileDialog::getOpenFileName(this, tr("Open file"),
                                         QDir::homePath(),
                                         tr("Multimedia files(*)"));

    if (file.isEmpty())
        return;

    _media = new VlcMedia(file, true, _instance);

    _player->open(_media);
}

void SimplePlayer::openUrl()
{

    /*char *rtsp_addr;
    rtsp_addr = (char *)malloc(100);
    memset(rtsp_addr, 0, 100);
    ONVIF_Capabilities(rtsp_addr);*/
            //QInputDialog::getText(this, tr("Open Url"), tr("Enter the URL you want to play"));

    QString url(rtsp_addr);
    //QString url = "rtsp://192.168.1.201:554/user=admin_password=EZDadSI1_channel=1_stream=0.sdp?real_stream";

    if (url.isEmpty())
        return;

    _media = new VlcMedia(url, _instance);
    _media->setOption("clock-synchro=-1");
    _media->setOption("rtsp-tcp");
    _media->setOption("rtsp-caching=10000");
    _media->setOption("clock-jitter=5000");
    _media->setOption("network-caching=333");

    _player->open(_media);
}
