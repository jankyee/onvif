/*
* VLC-Qt Simple Player
* Copyright (C) 2015 Tadej Novak <tadej@tano.si>
*/

#include <QtCore/QCoreApplication>
#include <QtWidgets/QApplication>

#include <VLCQtCore/Common.h>

#include "SimplePlayer.h"
#include "cap.h"

char *rtsp_addr;

int main(int argc, char *argv[])
{
    QCoreApplication::setApplicationName("VLC-Qt Simple Player");
    QCoreApplication::setAttribute(Qt::AA_X11InitThreads);

    QApplication app(argc, argv);
    VlcCommon::setPluginPath(app.applicationDirPath() + "/plugins");

    rtsp_addr = (char *)malloc(100);
    memset(rtsp_addr, 0, 100);
    ONVIF_Capabilities(rtsp_addr);

    SimplePlayer mainWindow;
    mainWindow.show();

    return app.exec();
}
